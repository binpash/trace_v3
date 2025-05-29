use anyhow::Result;
use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::os::unix::process::CommandExt;
use std::process::Command;
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

fn handle_event(data: &[u8]) -> i32 {
    println!("Got event");
    return data.len() as i32;
}

fn main() -> Result<()> {
    // let opts = Command::parse();

    // let fork = safe_fork()?;
    // if fork == Fork::Child {

    let args = std::env::args();

    // TODO (dan 2025-05-29): Decide whether or not we want to redirect the fd's to /dev/null
    let child;
    unsafe {
        child = Command::new("/bin/sh")
            .args(args.skip(1))
            .pre_exec(|| {
                let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY);
                libc::dup2(devnull, libc::STDOUT_FILENO);
                libc::dup2(devnull, libc::STDERR_FILENO);

                libc::pause();

                Ok(())
            })
            .spawn()?;
    }

    let pid = child.id();
    let pid_tgid = (pid as u64) << 32 | pid as u64;

    let cwd = std::env::current_dir()?
        .into_os_string()
        .into_string()
        .unwrap();
    let mut pid_cwd_map = HashMap::<u64, String>::new();
    pid_cwd_map.insert(pid_tgid, cwd.clone());

    let mut skel_builder = HsTraceSkelBuilder::default();
    // if opts.verbose {
    skel_builder.obj_builder.debug(true);
    // }

    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;

    // Begin tracing
    let mut skel = open_skel.load()?;
    skel.attach()?;

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
        libc::kill(pid as i32, libc::SIGCONT);
    }

    loop {
        match rb.poll(Duration::from_millis(10)) {
            Ok(()) => {}
            Err(_) => {}
        }
    }
}
