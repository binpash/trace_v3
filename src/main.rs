use anyhow::{Context, Result};
use clap::Parser;
use libbpf_rs::{MapCore, MapFlags, RingBufferBuilder};
use libc::{
    c_int, kill, sigaction, sigemptyset, sighandler_t, waitpid, SA_NOCLDSTOP, SA_RESTART, SIGCHLD,
    SIGCONT, SIGINT, SIGSTOP,
};
use nix::unistd::{setgroups, setresgid, setresuid, Gid, Uid};
use std::ffi::CStr;
use std::ffi::CString;
use std::io::{Error, ErrorKind};
use std::mem::{size_of, zeroed, MaybeUninit};
use std::os::raw::c_char;
use std::os::unix::io::RawFd;
use std::ptr;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

mod cli;
mod cli_def;
mod dep_tracer;
mod installer;
mod utils;

use crate::cli::{Cli, Commands, OutputMode, Outputs, StreamOutputs};
use crate::dep_tracer::{event_stream_handler, SyscallEvent, CTXT, LOGS, SETS};
use crate::installer::{installer, uninstall, Tracer};
use crate::utils::{invoker_permissions, resolve_executable};
use trace_v3::sys_enter_info_t;
use trace_v3::sys_exit_info_t;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
static RUNNING: AtomicBool = AtomicBool::new(true);

extern "C" fn sigchld_handler(_sig: i32) {
    RUNNING.store(false, Ordering::Relaxed);
}

extern "C" fn sigint_handler(_sig: i32) {
    RUNNING.store(false, Ordering::Relaxed);
}

fn monitor_pid(pid: i32) -> std::io::Result<RawFd> {
    unsafe {
        let fd = libc::syscall(libc::SYS_pidfd_open, pid, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(fd as RawFd)
    }
}

fn fork_child(cli: &Cli) -> Result<i32> {
    let tracee_pid: i32;
    unsafe {
        tracee_pid = libc::fork();
    }
    if tracee_pid < 0 {
        Err(Error::new(ErrorKind::Other, "couldn't fork"))?;
    }
    if tracee_pid == 0 {
        let executable_path = resolve_executable(&cli.cmd[0])?;
        let prog_str = executable_path
            .as_os_str()
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Executable path is not valid UTF-8"))?;

        unsafe {
            // prog
            let prog = CString::new(prog_str).expect("NUL byte in argument");

            // argv
            let cstr_args: Vec<CString> = cli
                .cmd
                .iter()
                .map(|s| CString::new(s.as_str()).expect("NUL byte in argument"))
                .collect();
            let mut argv: Vec<*const c_char> = cstr_args.iter().map(|s| s.as_ptr()).collect();
            argv.push(std::ptr::null());

            // envp
            let cstr_env: Vec<CString> = std::env::vars()
                .map(|(k, v)| CString::new(format!("{k}={v}")).expect("NUL byte in argument"))
                .collect();
            let mut envp: Vec<*const c_char> = cstr_env.iter().map(|s| s.as_ptr()).collect();
            envp.push(std::ptr::null());

            // de-escalate permissions
            let (uid, gid) = invoker_permissions()?;
            let target_uid = Uid::from_raw(uid);
            let target_gid = Gid::from_raw(gid);
            // Inside an unprivileged user namespace (e.g. `try`'s
            // `unshare --user`), setgroups(2) is unconditionally EPERM
            // regardless of effective capabilities — the kernel locks it off
            // when /proc/self/setgroups is "deny". No supplementary groups
            // exist to drop in that environment, so treat EPERM as a no-op.
            match setgroups(&[]) {
                Ok(()) | Err(nix::errno::Errno::EPERM) => {}
                Err(e) => panic!("setgroups: {e}"),
            }
            setresgid(target_gid, target_gid, target_gid).expect("setresgid");
            setresuid(target_uid, target_uid, target_uid).expect("setresuid");

            // wait for parent to signal that it's ready
            libc::raise(SIGSTOP);
            libc::execve(prog.as_ptr(), argv.as_ptr(), envp.as_ptr());
            libc::perror(b"execvp failed\0".as_ptr() as _);
            libc::_exit(127);
        }
    }
    Ok(tracee_pid)
}

fn main() -> Result<()> {


    let cli = Cli::parse();
    if let Some(Commands::Install {}) = cli.command {
        return installer();
    }
    if let Some(Commands::Uninstall {}) = cli.command {
        return uninstall();
    }

    // TODO: resolve the path of the executable before the fork
    // throw every other call until the path appears

    let mut tracee_pid = -1;
    let attach_to_existing_proc: bool;
    if let Some(Commands::Attach { pid }) = cli.command {
        tracee_pid = pid;
        attach_to_existing_proc = true;
    } else {
        attach_to_existing_proc = false;
    }

    let mut outputs = Outputs::from_cli(&cli)?;
    let stream_cfg = if matches!(cli.mode, OutputMode::Stream | OutputMode::Both) {
        let so = StreamOutputs::from_cli(&cli)?;
        Some(dep_tracer::StreamCfg {
            read_out: if cli.stream_read { Some(so.read) } else { None },
            write_out: if cli.stream_write {
                Some(so.write)
            } else {
                None
            },
            trace_out: if cli.stream_trace {
                Some(so.deps)
            } else {
                None
            },
        })
    } else {
        None
    };

    // either trace the pid or fork the child
    if !attach_to_existing_proc {
        match fork_child(&cli) {
            Ok(pid) => tracee_pid = pid,
            Err(e) => Err(e)?,
        }
    }

    // set up sighandler to detect when child terminates so we can reap
    // also handle SIGINT so we can clean up the tracer maps
    unsafe {
        let mut sa: sigaction = zeroed();
        sa.sa_sigaction = sigchld_handler as *const () as sighandler_t;
        sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
        sigemptyset(&mut sa.sa_mask);

        if sigaction(SIGCHLD, &sa, ptr::null_mut()) == -1 {
            Err(Error::new(
                ErrorKind::Other,
                "couldn't register sigchld handler",
            ))?;
        }

        sa.sa_sigaction = sigint_handler as *const () as sighandler_t;
        sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
        sigemptyset(&mut sa.sa_mask);

        if sigaction(SIGINT, &sa, ptr::null_mut()) == -1 {
            Err(Error::new(
                ErrorKind::Other,
                "couldn't register sigint handler",
            ))?
        }
    }

    let pid_tgid = (tracee_pid as u64) << 32 | tracee_pid as u64;

    let cwd = std::env::current_dir()?;
    // NOTE: map for userspace
    // let mut pid_cwd_map = HashMap::<u64, PathBuf>::new();
    // pid_cwd_map.insert(pid_tgid, cwd.clone());
    {
        let mut ctxt = CTXT.lock().unwrap();
        ctxt.init_pid(pid_tgid, cwd.clone());
        // Also initialize with just the pid (lower 32 bits) since some events might use that
        // ctxt.init_pid(target_pid as u64, cwd.clone());
        for entry in std::fs::read_dir(format!("/proc/{tracee_pid}/fd"))? {
            let entry = entry?;
            let fd: i32 = entry.file_name().to_string_lossy().parse().unwrap();
            let path = std::fs::read_link(entry.path())?;
            let fdinfo = std::fs::read_to_string(format!("/proc/{tracee_pid}/fdinfo/{fd}"))?;
            let start = fdinfo.find("flags:").unwrap() + 6;
            let end = start + fdinfo[start..].find('\n').unwrap();
            let status_flags = fdinfo[start..end].trim().parse::<u32>()?;

            ctxt.open_file(pid_tgid, fd, 0, status_flags, path);
        }
    }

    // Initialize the Tracer
    let tracer_pid = unsafe { libc::getpid() };
    let tracer_pid_buf = &tracer_pid.to_ne_bytes();
    let tracer = Tracer::new(tracer_pid, cli.ringbuf_size)
        .context("Failed to initialize tracer. Did you run `trace_v3 install`?")?;

    // update the pid_set for tracer
    let tracee_pid_buf = &tracee_pid.to_ne_bytes();

    tracer
        .pid_set
        .update(tracee_pid_buf, tracer_pid_buf, MapFlags::ANY)?;

    // create channel and spawn worker thread
    let (sender, receiver) = mpsc::channel::<Option<SyscallEvent>>();
    let stream_handler = thread::spawn(move || event_stream_handler(receiver, stream_cfg));

    let monitor_pid_fd = if let Ok(fd) = monitor_pid(tracee_pid) {
        Some(fd)
    } else {
        None
    };

    // setup ringbuf
    let measure_throughput = cli.throughput || cli.throughput_file.is_some();
    let bytes_received = Arc::new(AtomicU64::new(0));
    let events_received = Arc::new(AtomicU64::new(0));
    let bytes_received_rb = Arc::clone(&bytes_received);
    let events_received_rb = Arc::clone(&events_received);

    let mut rb_builder = RingBufferBuilder::new();
    rb_builder.add(&tracer.ringbuf, |data| {
        if measure_throughput {
            bytes_received_rb.fetch_add(data.len() as u64, Ordering::Relaxed);
            events_received_rb.fetch_add(1, Ordering::Relaxed);
        }
        let event = if data.len() == size_of::<sys_exit_info_t>() {
            let header = unsafe { &*data.as_ptr().cast::<sys_exit_info_t>() };
            SyscallEvent::Exit {
                pid_tgid: header.pid_tgid,
                ret: header.ret,
            }
        } else {
            let header_len = size_of::<sys_enter_info_t>();
            assert!(data.len() >= header_len);

            let header = unsafe { &*data.as_ptr().cast::<sys_enter_info_t>() };

            let path1_len = header.path1_len as usize;
            let path2_len = header.path2_len as usize;

            let path1_data = &data[header_len..(header_len + path1_len)];
            let path2_data = &data[(header_len + path1_len)..(header_len + path1_len + path2_len)];

            let path1 = if path1_len > 0 {
                CStr::from_bytes_with_nul(path1_data)
                    .expect("invalid C string")
                    .to_str()
                    .expect("should be valid str")
                    .to_string()
            } else {
                String::new()
            };
            let path2 = if path2_len > 0 {
                CStr::from_bytes_with_nul(path2_data)
                    .expect("invalid C string")
                    .to_str()
                    .expect("should be valid str")
                    .to_string()
            } else {
                String::new()
            };

            SyscallEvent::Enter {
                pid_tgid: header.pid_tgid,
                syscall_nr: header.syscall_nr,
                event_type: header.event_type,
                flags: header.flags,
                cmd: header.cmd,
                arg: header.arg,
                fd: header.fd,
                fd2: header.fd2,
                path1: path1,
                path2: path2,
            }
        };
        // handle all cases
        match sender.send(Some(event)) {
            Ok(_) => {}
            Err(_) => {}
        }
        return 0;
    })?;
    let rb = rb_builder.build()?;

    let key = 0u32.to_ne_bytes();
    let mut program_total = 0;
    let mut prev_missed = 0;
    let mut count = 0;

    // let num_cpus = libbpf_rs::num_possible_cpus()?;
    // let zero_init = vec![vec![0u8; 4]; num_cpus];
    //
    // tracer
    //     .missed
    //     .update_percpu(&key, &zero_init, MapFlags::ANY)?;

    // start the child
    unsafe {
        if !attach_to_existing_proc {
            kill(tracee_pid as i32, SIGCONT);
        }
    }

    let throughput_start = std::time::Instant::now();
    let throughput_interval = Duration::from_secs_f64(cli.throughput_interval.max(0.001));
    let mut last_tick = throughput_start;
    let mut last_bytes: u64 = 0;
    let mut last_events: u64 = 0;

    while RUNNING.load(Ordering::Relaxed) {
        match rb.poll(Duration::from_micros(25)) {
            Ok(()) => {}
            Err(_) => {}
        }
        if let Some(fd) = monitor_pid_fd {
            let mut pollfd = libc::pollfd {
                fd: fd,
                events: libc::POLLIN,
                revents: 0,
            };

            let ret = unsafe { libc::poll(&mut pollfd, 1, 0) };
            if ret > 0 {
                println!("Target process {} ended.", tracee_pid);
                RUNNING.store(false, Ordering::Relaxed);
            }
        }

        if let Some(count_per_cpu) = tracer.missed.lookup_percpu(&key, MapFlags::ANY)? {
            let mut total = 0;

            for missed in count_per_cpu {
                let slice = &missed[..size_of::<u32>()];
                let bytes: [u8; 4] = slice
                    .try_into()
                    .expect("missed_events entry was not exactly 4 bytes");
                let count = u32::from_ne_bytes(bytes);
                total += count;
            }
            let diff = total - prev_missed;
            if diff != 0 {
                println!(
                    "{diff} missed events in this poll,{count} before, {total} - {prev_missed}"
                );
                let logs = LOGS.lock().unwrap();
                count = 0;
                logs.size();
            } else {
                count += 1;
            }

            program_total += diff;
            prev_missed = total;
        };

        if measure_throughput {
            let tick_elapsed = last_tick.elapsed();
            if tick_elapsed >= throughput_interval {
                let now = throughput_start.elapsed().as_secs_f64();
                let cur_bytes = bytes_received.load(Ordering::Relaxed);
                let cur_events = events_received.load(Ordering::Relaxed);
                let delta_bytes = cur_bytes - last_bytes;
                let delta_events = cur_events - last_events;
                let interval_secs = tick_elapsed.as_secs_f64();
                let mb = delta_bytes as f64 / (1024.0 * 1024.0);
                let mb_per_sec = mb / interval_secs;
                let events_per_sec = delta_events as f64 / interval_secs;
                writeln!(
                    &mut outputs.throughput_file,
                    "[{now:8.3}s] {mb_per_sec:8.3} MB/s  {events_per_sec:8.0} events/s"
                )?;
                outputs.throughput_file.flush()?;
                last_tick = std::time::Instant::now();
                last_bytes = cur_bytes;
                last_events = cur_events;
            }
        }
    }

    let mut status = MaybeUninit::<c_int>::uninit();
    unsafe { if waitpid(tracee_pid, status.as_mut_ptr(), 0) != tracee_pid {} }

    // remove pid from map
    tracer.pid_set.lookup_and_delete(tracee_pid_buf)?;

    // send None to trigger thread to stop
    // TODO: handle all cases
    match sender.send(None) {
        Ok(_) => {}
        Err(_) => {}
    }
    let _ = stream_handler.join();
    if matches!(cli.mode, OutputMode::Summary | OutputMode::Both) {
        {
            let mut logs = LOGS.lock().unwrap();
            logs.dump_log(&mut outputs.trace_file)?;
        }
        {
            let mut sets = SETS.lock().unwrap();
            sets.dump_sets(&mut outputs.dep_file)?;
        }
    }
    // ctxt.check_empty();

    if cli.missed_file == "-" {
        writeln!(&mut outputs.missed_file, "missed {program_total} events")?;
    } else {
        writeln!(&mut outputs.missed_file, "{program_total}")?;
    }

    if measure_throughput {
        let elapsed = throughput_start.elapsed().as_secs_f64();
        let total_bytes = bytes_received.load(Ordering::Relaxed);
        let total_events = events_received.load(Ordering::Relaxed);
        let mb = total_bytes as f64 / (1024.0 * 1024.0);
        let mb_per_sec = if elapsed > 0.0 { mb / elapsed } else { 0.0 };
        let events_per_sec = if elapsed > 0.0 { total_events as f64 / elapsed } else { 0.0 };
        writeln!(
            &mut outputs.throughput_file,
            "summary: {total_events} events, {mb:.3} MB in {elapsed:.3}s (avg {mb_per_sec:.3} MB/s, {events_per_sec:.0} events/s)"
        )?;
    }

    Ok(())
}
