use anyhow::Result;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{Link, MapCore, MapFlags, MapHandle, MapImpl, MapType};
use std::os::fd::AsFd;
use std::os::unix::io::AsRawFd;
use std::{mem::MaybeUninit, path::PathBuf};

mod hs_trace {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/hs_trace.skel.rs"
    ));
}
use hs_trace::*;

const PIN_BASE: &str = "/sys/fs/bpf/trace_v3";

/// Pin a BPF link idempotently
fn pin_link(name: &str, link: &mut Option<Link>) -> Result<()> {
    if let Some(l) = link {
        let path = format!("{PIN_BASE}/{name}");
        if std::path::Path::new(&path).exists() {
            println!("Link {name} already pinned at {path}");
        } else {
            l.pin(&path)?;
            println!("Pinned link {name}");
        }
    } else {
        println!("Warning: Link {name} was not found in skeleton (None).");
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

    // Pin programs idempotently
    pin_link("enter_fcntl", &mut links.hs_trace_enter_fcntl)?;
    pin_link("enter_memfd_create", &mut links.hs_trace_enter_memfd_create)?;
    pin_link("enter_pipe2", &mut links.hs_trace_create_pipe)?;
    pin_link("exit_pipe2", &mut links.hs_trace_create_pipe_exit)?;
    pin_link("process_fork", &mut links.hs_trace_process_fork)?;
    pin_link("process_exit", &mut links.hs_trace_process_exit)?;
    pin_link("sys_enter", &mut links.hs_trace_sys_enter)?;
    pin_link("sys_exit", &mut links.hs_trace_sys_exit)?;

    // Pin maps idempotently
    pin_map("ringbufs", &skel.maps.ringbufs)?;
    pin_map("missed_events", &skel.maps.missed_events)?;
    pin_map("pid_set", &skel.maps.pid_set)?;

    println!("Pinned all programs and outer maps.");

    Ok(())
}

pub struct Tracer {
    tracer_pid: i32,
    ringbufs: MapHandle,
    missed_events: MapHandle,
    pub pid_set: MapHandle,
    pub ringbuf: MapHandle,
    pub missed: MapHandle,
}

impl Tracer {
    pub fn new(tracer_pid: i32, ringbuf_size: usize) -> Result<Self> {
        let mut opts: libbpf_sys::bpf_map_create_opts = unsafe { std::mem::zeroed() };
        opts.sz = std::mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t;

        // 1. Create unique inner maps for this specific tracer
        let ringbuf = MapHandle::create(
            MapType::RingBuf,
            Some(format!("ringbuf{tracer_pid}")),
            0,
            0,
            ringbuf_size as u32,
            &opts,
        )?;
        let missed = MapHandle::create(
            MapType::PercpuArray,
            Some(format!("missed_event{tracer_pid}")),
            4,
            4,
            1,
            &opts,
        )?;

        // 2. Get pinned outer maps
        let ringbufs = MapHandle::from_pinned_path("/sys/fs/bpf/trace_v3/ringbufs")?;
        let missed_events = MapHandle::from_pinned_path("/sys/fs/bpf/trace_v3/missed_events")?;
        let pid_set = MapHandle::from_pinned_path("/sys/fs/bpf/trace_v3/pid_set")?;

        // 3. Map them via the tracer_pid
        let tracer_pid_bytes = tracer_pid.to_ne_bytes();

        let ringbuf_fd = ringbuf.as_fd().as_raw_fd();
        let missed_fd = missed.as_fd().as_raw_fd();

        ringbufs.update(&tracer_pid_bytes, &ringbuf_fd.to_ne_bytes(), MapFlags::ANY)?;
        missed_events.update(&tracer_pid_bytes, &missed_fd.to_ne_bytes(), MapFlags::ANY)?;

        Ok(Self {
            tracer_pid,
            ringbufs,
            missed_events,
            pid_set,
            ringbuf,
            missed,
        })
    }
}

impl Drop for Tracer {
    fn drop(&mut self) {
        let tracer_pid_bytes = self.tracer_pid.to_ne_bytes();
        let _ = self.ringbufs.delete(&tracer_pid_bytes);
        let _ = self.missed_events.delete(&tracer_pid_bytes);
    }
}
