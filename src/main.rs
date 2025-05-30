use anyhow::Result;
use libc::{
    O_WRONLY, SA_NOCLDSTOP, SA_RESTART, SIG_BLOCK, SIGCHLD, SIGUSR1, STDERR_FILENO, STDOUT_FILENO,
    c_int, dup2, kill, open, sigaction, sigaddset, sigemptyset, sighandler_t, sigprocmask,
    sigset_t, sigwait, waitpid,
};
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::mem::{MaybeUninit, size_of, transmute, zeroed};
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::ptr;
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

fn handle_event(data: &[u8]) -> i32 {
    println!("Got event of length {}", data.len());
    if data.len() == size_of::<sys_enter_info0_t>() {
        let enter0 = unsafe { &*data.as_ptr().cast::<sys_enter_info0_t>() };
        println!(
            "for ({}, {}) {}(flags={})",
            enter0.pid >> 32,
            enter0.pid & 0xFFFFFFFF,
            enter0.syscall_nr,
            enter0.flags
        );
    }
    if data.len() == size_of::<sys_enter_info1_t>() {
        let enter1 = unsafe { &*data.as_ptr().cast::<sys_enter_info1_t>() };
        println!(
            "for ({}, {}) {}(fd={},path={},flags={})",
            enter1.pid >> 32,
            enter1.pid & 0xFFFFFFFF,
            enter1.syscall_nr,
            enter1.fd,
            String::from_utf8(enter1.path[..].to_vec()).unwrap(),
            enter1.flags
        );
    }
    if data.len() == size_of::<sys_enter_info2_t>() {
        let enter2 = unsafe { &*data.as_ptr().cast::<sys_enter_info2_t>() };
        println!(
            "for ({}, {}) {}(fd={},path={},fd2={},path2={},flags={})",
            enter2.pid >> 32,
            enter2.pid & 0xFFFFFFFF,
            enter2.syscall_nr,
            enter2.fd,
            String::from_utf8(enter2.path[..].to_vec()).unwrap(),
            enter2.fd2,
            String::from_utf8(enter2.path2[..].to_vec()).unwrap(),
            enter2.flags
        );
    }
    if data.len() == size_of::<sys_exit_info_t>() {
        let exit = unsafe { &*data.as_ptr().cast::<sys_exit_info_t>() };
        println!(
            "for ({}, {}) -> {}",
            exit.pid >> 32,
            exit.pid & 0xFFFFFFFF,
            exit.ret
        );
    }
    return 0;
}

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

    let pid;
    unsafe {
        pid = libc::fork();
    }
    if pid < 0 {
        Err(Error::new(ErrorKind::Other, "couldn't fork"))?;
    }
    if pid == 0 {
        unsafe {
            // TODO (dan 2025-05-29): Decide whether or not we want to redirect the fd's to /dev/null
            let devnull = open(c"/dev/null".as_ptr(), O_WRONLY);
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);

            let mut set: sigset_t = zeroed();
            sigemptyset(&mut set);
            sigaddset(&mut set, SIGUSR1);
            sigprocmask(SIG_BLOCK, &mut set, ptr::null_mut());

            let mut sig = zeroed();
            if sigwait(&mut set, &mut sig) != 0 {
                Err(Error::new(ErrorKind::Other, "couldn't sigwait"))?;
            }
            let _ = Command::new(args.nth(1).unwrap()).args(args.skip(1)).exec();
        }
    }

    let pid_tgid = (pid as u64) << 32 | pid as u64;

    let cwd = std::env::current_dir()?
        .into_os_string()
        .into_string()
        .unwrap();
    // NOTE: map for userspace.
    let mut pid_cwd_map = HashMap::<u64, String>::new();
    pid_cwd_map.insert(pid_tgid, cwd.clone());

    let skel_builder = HsTraceSkelBuilder::default();
    // if opts.verbose {
    //     skel_builder.obj_builder.debug(true);
    // }

    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;

    // Begin tracing
    let mut skel = open_skel.load()?;
    skel.attach()?;

    // TODO: check if this should be little endian!
    let pid_buf = &pid_tgid.to_le_bytes();
    let mut cwd_bytes = cwd.into_bytes();
    cwd_bytes.resize(4096, 0);
    let cwd_buf = &cwd_bytes;
    let _ = skel
        .maps
        .pid_cwd_map
        .update(pid_buf, cwd_buf, MapFlags::ANY)?;

    let mut rb_builder = RingBufferBuilder::new();
    rb_builder.add(&skel.maps.output, handle_event)?;
    let rb = rb_builder.build()?;

    unsafe {
        kill(pid as i32, SIGUSR1);
    }

    while RUNNING.load(Ordering::Relaxed) {
        match rb.poll(Duration::from_millis(10)) {
            Ok(()) => {}
            Err(_) => {}
        }
    }

    let mut status = MaybeUninit::<c_int>::uninit();
    unsafe { if waitpid(pid, status.as_mut_ptr(), 0) != pid {} }

    Ok(())
}
