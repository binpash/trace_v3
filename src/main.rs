use anyhow::Result;
use clap::Parser;
use libbpf_rs::{MapCore, MapFlags, MapHandle, RingBufferBuilder};
use libc::{
    c_int, kill, sigaction, sigaddset, sigemptyset, sighandler_t, sigprocmask, sigset_t, sigwait,
    waitpid, SA_NOCLDSTOP, SA_RESTART, SIGCHLD, SIGUSR1, SIG_BLOCK, SIG_UNBLOCK,
};
use nix::unistd::{getgid, getuid, setgroups, setresgid, setresuid, Gid, Uid};
use std::ffi::CStr;
use std::ffi::CString;
use std::io::{Error, ErrorKind};
use std::mem::{size_of, zeroed, MaybeUninit};
use std::os::raw::c_char;
use std::os::unix::io::RawFd;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use std::{env, ptr};

mod cli;
mod dep_tracer;
mod installer;

use crate::cli::{Cli, Commands, Outputs};
use crate::dep_tracer::event_stream_handler;
use crate::dep_tracer::SyscallEvent;
use crate::dep_tracer::{CTXT, LOGS, SETS};
use crate::installer::installer;
use trace_v3::sys_enter_info_t;
use trace_v3::sys_exit_info_t;

use std::sync::atomic::{AtomicBool, Ordering};
static RUNNING: AtomicBool = AtomicBool::new(true);

extern "C" fn sigchld_handler(_sig: i32) {
    RUNNING.store(false, Ordering::Relaxed);
}

fn invoker_permissions() -> Result<(u32, u32)> {
    let uid = match env::var("SUDO_UID").ok() {
        Some(uid) => uid.parse()?,
        None => getuid().as_raw(), // if invoking with setuid, use ruid
    };
    let gid = match env::var("SUDO_GID").ok() {
        Some(gid) => gid.parse()?,
        None => getgid().as_raw(), // if invoking with setuid, use rgid
    };
    Ok((uid, gid))
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
    let target_pid: i32;
    unsafe {
        target_pid = libc::fork();
    }
    if target_pid < 0 {
        Err(Error::new(ErrorKind::Other, "couldn't fork"))?;
    }
    if target_pid == 0 {
        unsafe {
            let mut set: sigset_t = zeroed();

            // block SIGUSR1, so it can become pending
            sigemptyset(&mut set);
            sigaddset(&mut set, SIGUSR1);
            sigprocmask(SIG_BLOCK, &mut set, ptr::null_mut());

            // wait on SIGUSR1
            let mut sig = zeroed();
            if sigwait(&mut set, &mut sig) != 0 {
                Err(Error::new(ErrorKind::Other, "couldn't sigwait"))?;
            }

            // unblock SIGUSR1
            sigemptyset(&mut set);
            sigprocmask(SIG_UNBLOCK, &mut set, ptr::null_mut());

            let cstr_args: Vec<CString> = cli
                .cmd
                .iter()
                .map(|s| CString::new(s.as_str()).expect("NUL byte in argument"))
                .collect();

            // build argv
            let mut argv: Vec<*const c_char> = cstr_args.iter().map(|s| s.as_ptr()).collect();
            argv.push(std::ptr::null());

            let prog = &cstr_args[0];

            let (uid, gid) = invoker_permissions()?;
            let target_uid = Uid::from_raw(uid);
            let target_gid = Gid::from_raw(gid);
            setgroups(&[]).expect("setgroups");
            setresgid(target_gid, target_gid, target_gid).expect("setresgid");
            setresuid(target_uid, target_uid, target_uid).expect("setresuid");

            libc::execvp(prog.as_ptr(), argv.as_ptr());
            libc::perror(b"execvp failed\0".as_ptr() as _);
            libc::_exit(127);
        }
    }
    Ok(target_pid)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Some(Commands::Install {}) = cli.command {
        return installer();
    }

    // TODO: resolve the path of the executable before the fork
    // throw every other call until the path appears

    let mut target_pid = -1;
    let attach_to_existing_proc: bool;
    if let Some(Commands::Attach { pid }) = cli.command {
        target_pid = pid;
        attach_to_existing_proc = true;
    } else {
        attach_to_existing_proc = false;
    }

    let mut outputs = Outputs::from_cli(&cli)?;

    // set up sighandler to detect when child terminates so we can reap
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
    }

    // either trace the pid or fork the child
    if !attach_to_existing_proc {
        match fork_child(&cli) {
            Ok(pid) => target_pid = pid,
            Err(e) => Err(e)?,
        }
    }

    let pid_tgid = (target_pid as u64) << 32 | target_pid as u64;

    let cwd = std::env::current_dir()?;
    // NOTE: map for userspace
    // let mut pid_cwd_map = HashMap::<u64, PathBuf>::new();
    // pid_cwd_map.insert(pid_tgid, cwd.clone());
    {
        let mut ctxt = CTXT.lock().unwrap();
        ctxt.init_pid(pid_tgid, cwd.clone());
        // Also initialize with just the pid (lower 32 bits) since some events might use that
        // ctxt.init_pid(target_pid as u64, cwd.clone());
        for entry in std::fs::read_dir(format!("/proc/{target_pid}/fd"))? {
            let entry = entry?;
            let fd: i32 = entry.file_name().to_string_lossy().parse().unwrap();
            let path = std::fs::read_link(entry.path())?;
            let fdinfo = std::fs::read_to_string(format!("/proc/{target_pid}/fdinfo/{fd}"))?;
            let start = fdinfo.find("flags:").unwrap() + 6;
            let end = start + fdinfo[start..].find('\n').unwrap();
            let status_flags = fdinfo[start..end].trim().parse::<u32>()?;

            ctxt.open_file(pid_tgid, fd, 0, status_flags, path);
        }
    }

    // update the map
    // let runner_pid = unsafe { libc::getpid() };
    // println!("parent: {runner_pid} child: {target_pid}");
    let target_pid_buf = &target_pid.to_ne_bytes();
    let dummy_val: i32 = 1;
    let dummy_bytes = &dummy_val.to_ne_bytes();

    let pid_set = MapHandle::from_pinned_path("/sys/fs/bpf/hs_trace_pid_set")?;
    pid_set.update(target_pid_buf, dummy_bytes, MapFlags::ANY)?;

    // create channel and spawn worker thread
    let (sender, receiver) = mpsc::channel::<Option<SyscallEvent>>();
    let stream_handler = thread::spawn(move || event_stream_handler(receiver));

    let monitor_pid_fd = if let Ok(fd) = monitor_pid(target_pid) {
        Some(fd)
    } else {
        None
    };

    // setup ringbuf
    let rb_map = MapHandle::from_pinned_path("/sys/fs/bpf/hs_trace_output")?;
    let mut rb_builder = RingBufferBuilder::new();
    rb_builder.add(&rb_map, |data| {
        // println!("received {} bytes", data.len());
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

    let missed_events = MapHandle::from_pinned_path("/sys/fs/bpf/hs_trace_missed_events")?;

    let key = 0u32.to_ne_bytes();
    let mut program_total = 0;
    let mut prev_missed = 0;
    let mut count = 0;

    // start the child
    unsafe {
        if !attach_to_existing_proc {
            kill(target_pid as i32, SIGUSR1);
        }
    }

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
                println!("Target process {} ended.", target_pid);
                RUNNING.store(false, Ordering::Relaxed);
            }
        }

        if let Some(count_per_cpu) = missed_events.lookup_percpu(&key, MapFlags::ANY)? {
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
    }

    let mut status = MaybeUninit::<c_int>::uninit();
    unsafe { if waitpid(target_pid, status.as_mut_ptr(), 0) != target_pid {} }

    // remove pid from map
    pid_set.lookup_and_delete(target_pid_buf)?;

    // send None to trigger thread to stop
    // TODO: handle all cases
    match sender.send(None) {
        Ok(_) => {}
        Err(_) => {}
    }
    let _ = stream_handler.join();
    // let ctxt = CTXT.lock().unwrap();
    let mut logs = LOGS.lock().unwrap();
    logs.dump_log(&mut outputs.trace_file)?;

    let mut sets = SETS.lock().unwrap();
    sets.dump_sets(&mut outputs.dep_file)?;
    // ctxt.check_empty();

    // let potential_added_dirs = ["git", "temp"];
    //
    // if cfg!(debug_assertions) {
    //     for dir in potential_added_dirs {
    //         let path = PathBuf::from(dir);
    //         if path.is_dir() {
    //             println!("Removing directory: {}", dir);
    //             if let Err(e) = fs::remove_dir_all(path) {
    //                 eprintln!("Failed to remove {}: {}", dir, e);
    //             }
    //         } else {
    //             println!("No such directory: {}", dir);
    //         }
    //     }
    // }

    println!("{program_total} missed events during the duration of the program");
    Ok(())
}
