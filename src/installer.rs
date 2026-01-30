use anyhow::Result;
use libbpf_rs::Link;

mod hs_trace {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/hs_trace.skel.rs"
    ));
}

use hs_trace::*;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapHandle, MapImpl};
use std::{mem::MaybeUninit, path::PathBuf};

const PIN_BASE: &str = "/sys/fs/bpf";

/// Pin a link idempotently
fn pin_link(name: &str, link: &mut Option<Link>) -> Result<()> {
    if let Some(l) = link {
        let path = format!("{PIN_BASE}/{name}");
        if PathBuf::from(&path).exists() {
            println!("Link {name} already pinned at {path}");
        } else {
            l.pin(&path)?;
            println!("Pinned link {name}");
        }
    }
    Ok(())
}

fn pin_map(name: &str, map: &MapImpl<'_>) -> Result<()> {
    let path = format!("{PIN_BASE}/{name}");

    if PathBuf::from(&path).exists() {
        println!("Map {name} already pinned at {path}");
        return Ok(());
    }

    // Convert MapImpl to MapHandle
    let mut handle = MapHandle::try_from(map)?;
    handle.pin(&path)?;
    println!("Pinned map {name}");

    Ok(())
}

pub fn installer() -> Result<()> {
    std::fs::create_dir_all(PIN_BASE)?;

    let skel_builder = HsTraceSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();

    let open_skel = skel_builder.open(&mut open_object)?;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    println!("Loaded and attached programs.");

    let links = &mut skel.links;

    // Pin links idempotently
    pin_link("hs_trace_enter_fcntl", &mut links.hs_trace_enter_fcntl)?;
    pin_link(
        "hs_trace_enter_memfd_create",
        &mut links.hs_trace_enter_memfd_create,
    )?;
    pin_link("hs_trace_create_pipe", &mut links.hs_trace_create_pipe)?;
    pin_link(
        "hs_trace_create_pipe_exit",
        &mut links.hs_trace_create_pipe_exit,
    )?;
    pin_link("hs_trace_process_fork", &mut links.hs_trace_process_fork)?;
    pin_link("hs_trace_process_exit", &mut links.hs_trace_process_exit)?;
    pin_link("hs_trace_sys_enter", &mut links.hs_trace_sys_enter)?;
    pin_link("hs_trace_sys_exit", &mut links.hs_trace_sys_exit)?;

    // Pin maps idempotently
    pin_map("hs_trace_output", &skel.maps.output)?;
    pin_map("hs_trace_pid_set", &skel.maps.pid_set)?;
    pin_map("hs_trace_missed_events", &skel.maps.missed_events)?;

    println!("Pinned all maps and links.");

    Ok(())
}
