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

const PIN_BASE: &str = "/sys/fs/bpf/fstrace";

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
    pin_map("dead_tracers", &skel.maps.dead_tracers)?;

    println!("Pinned all programs and outer maps.");

    Ok(())
}

pub fn uninstall() -> Result<()> {
    if std::path::Path::new(PIN_BASE).exists() {
        std::fs::remove_dir_all(PIN_BASE)?;
        println!("Uninstalled BPF programs and maps from {}", PIN_BASE);
    } else {
        println!("Nothing to uninstall. {} does not exist.", PIN_BASE);
    }
    Ok(())
}

/// Is a pid still running? EPERM counts as alive: the process exists, it simply
/// belongs to someone else.
fn pid_is_alive(pid: i32) -> bool {
    if unsafe { libc::kill(pid, 0) } == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Free ringbufs/missed_events slots whose tracer has exited.
///
/// The BPF exit hook records the deaths (it cannot modify a map of maps
/// itself); this turns those records into actual reclaims.
fn reclaim_dead_tracers(ringbufs: &MapHandle, missed_events: &MapHandle, dead_tracers: &MapHandle) {
    // Collect before mutating: bpf_map_get_next_key restarts iteration when
    // handed a key that has since been deleted, so deleting mid-iteration can
    // revisit entries or never terminate. The map is capacity bound, so this
    // is a handful of keys at most.
    let keys: Vec<Vec<u8>> = dead_tracers.keys().collect();
    for key in keys {
        let Ok(bytes) = <[u8; 4]>::try_from(key.as_slice()) else {
            let _ = dead_tracers.delete(&key);
            continue;
        };
        let pid = i32::from_ne_bytes(bytes);

        // A pid can be recycled between the exit hook recording it and this
        // sweep, and its new owner may be a tracer that has already claimed the
        // slot under that same key. Freeing it then would pull the slot out
        // from under a running tracer, so leave anything still alive alone and
        // just drop the stale record.
        if !pid_is_alive(pid) {
            let _ = ringbufs.delete(&key);
            let _ = missed_events.delete(&key);
        }
        let _ = dead_tracers.delete(&key);
    }
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
        let ringbufs = MapHandle::from_pinned_path("/sys/fs/bpf/fstrace/ringbufs")?;
        let missed_events = MapHandle::from_pinned_path("/sys/fs/bpf/fstrace/missed_events")?;
        let pid_set = MapHandle::from_pinned_path("/sys/fs/bpf/fstrace/pid_set")?;
        let dead_tracers = MapHandle::from_pinned_path("/sys/fs/bpf/fstrace/dead_tracers")?;

        // 2b. Reclaim slots left by tracers that were killed before they could
        // deregister. Done on every start rather than only after a failed
        // claim: the map is empty in the common case, so this is one extra
        // syscall against the 4MB ring buffer allocated just above, while
        // reclaiming lazily would mean a tracer has to fail — and in a
        // speculating supervisor a failed tracer costs a discarded execution.
        // Keeping it near-empty also matters because dead_tracers is capacity
        // bound like the maps it guards; once full, the kernel silently stops
        // recording deaths and those slots leak with no way to find them again.
        reclaim_dead_tracers(&ringbufs, &missed_events, &dead_tracers);

        // 3. Map them via the tracer_pid
        let tracer_pid_bytes = tracer_pid.to_ne_bytes();

        // Claiming this pid supersedes any death recorded against it by an
        // earlier tracer that happened to hold the same pid, so drop that
        // record instead of letting a later sweep act on it.
        let _ = dead_tracers.delete(&tracer_pid_bytes);

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
