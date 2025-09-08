use anyhow::Result;
use libbpf_sys::libbpf_num_possible_cpus;
use libbpf_sys::{
    BPF_FUNC_map_lookup_percpu_elem, bpf_map__fd, bpf_map__lookup_elem, bpf_map_lookup_elem,
};
use libc::{
    O_WRONLY, SA_NOCLDSTOP, SA_RESTART, SIG_BLOCK, SIGCHLD, SIGUSR1, STDERR_FILENO, STDOUT_FILENO,
    c_int, dup2, kill, open, sigaction, sigaddset, sigemptyset, sighandler_t, sigprocmask,
    sigset_t, sigwait, waitpid,
};
use std::collections::HashMap;
use std::ffi::CStr;
use std::ffi::CString;
use std::io::{Error, ErrorKind};
use std::mem::{MaybeUninit, size_of, zeroed};
use std::os::fd::{AsFd, AsRawFd};
use std::os::raw::c_char;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::ptr;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
// use clap::Parser;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, RingBufferBuilder};
// use plain::Plain;
// use time::OffsetDateTime;
// use time::macros::format_description;

mod hs_trace {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/hs_trace.skel.rs"
    ));
}

#[allow(clippy::wildcard_imports)]
use hs_trace::*;
use trace_v3::*;

mod dep_tracer;
use crate::dep_tracer::SyscallEvent;
use crate::dep_tracer::event_stream_handler;
use crate::dep_tracer::{CTXT, LOGS, SETS};

use std::sync::atomic::{AtomicBool, Ordering};
static RUNNING: AtomicBool = AtomicBool::new(true);

extern "C" fn sigchld_handler(_sig: i32) {
    RUNNING.store(false, Ordering::Relaxed);
}

fn main() -> Result<()> {
    let mut args = std::env::args();

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
            sigprocmask(SIG_BLOCK, &mut set, ptr::null_mut());

            let mut sig = zeroed();
            if sigwait(&mut set, &mut sig) != 0 {
                Err(Error::new(ErrorKind::Other, "couldn't sigwait"))?;
            }

            let cstr_args: Vec<CString> = args
                .skip(1)
                .map(|s| CString::new(s.as_str()).expect("invalid C string"))
                .collect();

            let mut argv: Vec<*const c_char> = cstr_args.iter().map(|s| s.as_ptr()).collect();
            argv.push(std::ptr::null());
            let prog = &cstr_args[0];
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

    let skel_builder = HsTraceSkelBuilder::default();
    // if opts.verbose {
    //     skel_builder.obj_builder.debug(true);
    // }

    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;

    // Begin tracing
    let mut skel = open_skel.load()?;
    skel.attach()?;

    // update the map
    let runner_pid = unsafe { libc::getpid() };
    println!("parent: {runner_pid} child: {target_pid}");
    // TODO: check if native endianness is correct!
    let runner_pid_buf = &runner_pid.to_ne_bytes();
    let target_pid_buf = &target_pid.to_ne_bytes();
    let dummy_val: i32 = 1;
    let dummy_bytes = &dummy_val.to_ne_bytes();
    // skel.maps
    //     .pid_set
    //     .update(runner_pid_buf, dummy_bytes, MapFlags::ANY)?;
    skel.maps
        .pid_set
        .update(target_pid_buf, dummy_bytes, MapFlags::ANY)?;

    // create channel and spawn worker thread
    let (sender, receiver) = mpsc::channel::<Option<SyscallEvent>>();
    let stream_handler = thread::spawn(move || event_stream_handler(receiver));

    // setup ringbuf
    let mut rb_builder = RingBufferBuilder::new();
    rb_builder.add(&skel.maps.output, |data| {
        let event = if data.len() == size_of::<sys_enter_info0_t>() {
            SyscallEvent::Enter0(unsafe { *data.as_ptr().cast::<sys_enter_info0_t>() })
        } else if data.len() == size_of::<sys_enter_info1_t>() {
            SyscallEvent::Enter1(unsafe { *data.as_ptr().cast::<sys_enter_info1_t>() })
        } else if data.len() == size_of::<sys_enter_info2_t>() {
            SyscallEvent::Enter2(unsafe { *data.as_ptr().cast::<sys_enter_info2_t>() })
        } else if data.len() == size_of::<sys_exit_info_t>() {
            SyscallEvent::Exit(unsafe { *data.as_ptr().cast::<sys_exit_info_t>() })
        } else {
            panic!("invalid event size {}", data.len());
        };
        // handle all cases
        match sender.send(Some(event)) {
            Ok(_) => {}
            Err(_) => {}
        }
        return 0;
    })?;
    let rb = rb_builder.build()?;
    // start the child
    unsafe {
        kill(target_pid as i32, SIGUSR1);
    }
    let key = 0u32.to_ne_bytes();
    let mut program_total = 0;
    while RUNNING.load(Ordering::Relaxed) {
        match rb.poll(Duration::from_millis(10)) {
            Ok(()) => {}
            Err(_) => {}
        }
        if let Some(count_per_cpu) = skel.maps.missed_events.lookup_percpu(&key, MapFlags::ANY)? {
            let mut total = 0;
            for missed in count_per_cpu {
                let slice = &missed[..size_of::<u32>()];
                let bytes: [u8; 4] = slice
                    .try_into()
                    .expect("missed_events entry was not exactly 4 bytes");
                let count = u32::from_ne_bytes(bytes);
                total += count;
            }
            if total != 0 {
                println!("{total} missed events in this poll");
            }
            program_total += total;
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
    let ctxt = CTXT.lock().unwrap();
    let mut logs = LOGS.lock().unwrap();
    logs.dump_log();

    let mut sets = SETS.lock().unwrap();

    sets.dump_sets();   
    ctxt.check_empty();
    Ok(())
}
