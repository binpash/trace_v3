use anyhow::Result;
use libc::{
    c_int, kill, sigaction, sigaddset, sigemptyset, sighandler_t, sigprocmask, sigset_t, sigwait,
    waitpid, SA_NOCLDSTOP, SA_RESTART, SIGCHLD, SIGUSR1, SIG_BLOCK, SIG_UNBLOCK,
};
use std::ffi::CStr;
use std::ffi::CString;
use std::io::{Error, ErrorKind};
use std::mem::{size_of, zeroed, MaybeUninit};
use std::os::raw::c_char;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use std::{env, fs, ptr};
// use clap::Parser;
use libbpf_rs::{MapCore, MapFlags, MapHandle, RingBufferBuilder};
use nix::unistd::{setgroups, setresgid, setresuid, Gid, Uid};
// use plain::Plain;
// use time::OffsetDateTime;
// use time::macros::format_description;

#[allow(clippy::wildcard_imports)]
use trace_v3::*;

mod dep_tracer;
use crate::dep_tracer::event_stream_handler;
use crate::dep_tracer::SyscallEvent;
use crate::dep_tracer::{CTXT, LOGS, SETS};

use std::sync::atomic::{AtomicBool, Ordering};
static RUNNING: AtomicBool = AtomicBool::new(true);

extern "C" fn sigchld_handler(_sig: i32) {
    RUNNING.store(false, Ordering::Relaxed);
}
fn find_sudo_invoker() -> Option<(u32, u32)> {
    let sudo = env::var("SUDO_UID").ok()?;
    let prev_uid: u32 = match sudo.trim().parse() {
        Ok(num) => num,
        Err(_) => 0,
    };

    let group = env::var("SUDO_GID").ok()?;
    let prev_grp: u32 = match group.trim().parse() {
        Ok(num) => num,
        Err(_) => 0,
    };
    Some((prev_uid, prev_grp))
}
fn main() -> Result<()> {
    let args = std::env::args();

    unsafe {
        let mut sa: sigaction = zeroed();
        sa.sa_sigaction = sigchld_handler as sighandler_t;
        sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
        sigemptyset(&mut sa.sa_mask);

        if sigaction(SIGCHLD, &sa, ptr::null_mut()) == -1 {
            Err(Error::new(
                ErrorKind::Other,
                "couldn't register sigchld handler",
            ))?;
        }
    }

    let target_pid;
    unsafe {
        target_pid = libc::fork();
    }
    if target_pid < 0 {
        Err(Error::new(ErrorKind::Other, "couldn't fork"))?;
    }
    if target_pid == 0 {
        unsafe {
            let mut set: sigset_t = zeroed();
            sigemptyset(&mut set);
            sigaddset(&mut set, SIGUSR1);

            // block SIGUSR1, so it can become pending
            sigprocmask(SIG_BLOCK, &mut set, ptr::null_mut());

            // wait on SIGUSR1
            let mut sig = zeroed();
            if sigwait(&mut set, &mut sig) != 0 {
                Err(Error::new(ErrorKind::Other, "couldn't sigwait"))?;
            }

            // unblock SIGUSR1
            sigemptyset(&mut set);
            sigprocmask(SIG_UNBLOCK, &mut set, ptr::null_mut());

            let cstr_args: Vec<CString> = args
                .skip(1)
                .map(|s| CString::new(s.as_str()).expect("invalid C string"))
                .collect();

            let mut argv: Vec<*const c_char> = cstr_args.iter().map(|s| s.as_ptr()).collect();
            argv.push(std::ptr::null());
            let prog = &cstr_args[0];

            match find_sudo_invoker() {
                Some((uid, gid)) => {
                    let target_uid = Uid::from_raw(uid);
                    let target_gid = Gid::from_raw(gid);
                    setgroups(&[]).expect("setgroups");

                    setresgid(target_gid, target_gid, target_gid).expect("setresgid");
                    setresuid(target_uid, target_uid, target_uid).expect("setresuid");
                }
                None => {}
            }

            libc::execvp(prog.as_ptr(), argv.as_ptr());
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

    // let skel_builder = HsTraceSkelBuilder::default();
    // // if opts.verbose {
    // //     skel_builder.obj_builder.debug(true);
    // // }
    //
    // let mut open_object = MaybeUninit::uninit();
    // let open_skel = skel_builder.open(&mut open_object)?;
    //
    // // Begin tracing
    // let mut skel = open_skel.load()?;
    // skel.attach()?;

    // update the map
    let runner_pid = unsafe { libc::getpid() };
    println!("parent: {runner_pid} child: {target_pid}");
    // TODO: check if native endianness is correct!
    let target_pid_buf = &target_pid.to_ne_bytes();
    let dummy_val: i32 = 1;
    let dummy_bytes = &dummy_val.to_ne_bytes();

    let pid_set = MapHandle::from_pinned_path("/sys/fs/bpf/hs_trace_pid_set")?;
    pid_set.update(target_pid_buf, dummy_bytes, MapFlags::ANY)?;

    // create channel and spawn worker thread
    let (sender, receiver) = mpsc::channel::<Option<SyscallEvent>>();
    let stream_handler = thread::spawn(move || event_stream_handler(receiver));

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
    // start the child
    unsafe {
        kill(target_pid as i32, SIGUSR1);
    }
    let key = 0u32.to_ne_bytes();
    let mut program_total = 0;
    let mut prev_missed = 0;
    let mut count = 0;
    while RUNNING.load(Ordering::Relaxed) {
        match rb.poll(Duration::from_micros(25)) {
            Ok(()) => {}
            Err(_) => {}
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
    println!("{program_total} missed events during the duration of the program");

    let mut status = MaybeUninit::<c_int>::uninit();
    unsafe { if waitpid(target_pid, status.as_mut_ptr(), 0) != target_pid {} }

    // send None to trigger thread to stop
    // TODO: handle all cases
    match sender.send(None) {
        Ok(_) => {}
        Err(_) => {}
    }
    let _ = stream_handler.join();
    // let ctxt = CTXT.lock().unwrap();
    let mut logs = LOGS.lock().unwrap();
    logs.dump_log();

    let mut sets = SETS.lock().unwrap();

    sets.dump_sets();
    // ctxt.check_empty();
    let potential_added_dirs = ["git", "temp"];

    if cfg!(debug_assertions) {
        for dir in potential_added_dirs {
            let path = PathBuf::from(dir);
            if path.is_dir() {
                println!("Removing directory: {}", dir);
                if let Err(e) = fs::remove_dir_all(path) {
                    eprintln!("Failed to remove {}: {}", dir, e);
                }
            } else {
                println!("No such directory: {}", dir);
            }
        }
    }
    println!("{program_total} missed events during the duration of the program");
    Ok(())
}
