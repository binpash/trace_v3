use anyhow::Result;
use std::collections::HashMap;
use std::ffi::CStr;
use std::path::PathBuf;
use std::sync::mpsc;
use trace_v3::*;

pub enum SyscallEvent {
    Enter0(sys_enter_info0_t),
    Enter1(sys_enter_info1_t),
    Enter2(sys_enter_info2_t),
    Exit(sys_exit_info_t),
}

struct Context {
    cwd_map: HashMap<u64, PathBuf>,
    log: HashMap<u64, Vec<SyscallEvent>>,
    process_graph: HashMap<u64, u64>,
}

impl Context {
    fn new() -> Context {
        Context {
            cwd_map: HashMap::new(),
            log: HashMap::new(),
            process_graph: HashMap::new(),
        }
    }

    pub fn do_clone(&mut self, parent_pid_tgid: u64, child_pid_tgid: u64) -> () {
        self.process_graph.insert(child_pid_tgid, parent_pid_tgid);
        let parent_cwd = self.cwd_map.get(&parent_pid_tgid).unwrap();
        self.cwd_map.insert(child_pid_tgid, parent_cwd.clone());
    }
}

pub fn event_stream_handler(rx: mpsc::Receiver<Option<SyscallEvent>>) -> Result<()> {
    loop {
        match rx.recv() {
            Ok(Some(SyscallEvent::Enter0(e))) => {
                println!(
                    "for ({}, {}) {}(flags={})",
                    e.pid >> 32,
                    e.pid & 0xFFFFFFFF,
                    e.syscall_nr,
                    e.flags
                );
            }
            Ok(Some(SyscallEvent::Enter1(e))) => {
                let cstr = unsafe { CStr::from_ptr(e.path.as_ptr()) };
                println!(
                    "for ({}, {}) {}(fd={},path={},flags={})",
                    e.pid >> 32,
                    e.pid & 0xFFFFFFFF,
                    e.syscall_nr,
                    e.fd,
                    cstr.to_string_lossy(),
                    e.flags
                );
            }
            Ok(Some(SyscallEvent::Enter2(e))) => {
                let cstr = unsafe { CStr::from_ptr(e.path.as_ptr()) };
                let cstr2 = unsafe { CStr::from_ptr(e.path2.as_ptr()) };
                println!(
                    "for ({}, {}) {}(fd={},path={},fd2={},path2={},flags={})",
                    e.pid >> 32,
                    e.pid & 0xFFFFFFFF,
                    e.syscall_nr,
                    e.fd,
                    cstr.to_string_lossy(),
                    e.fd2,
                    cstr2.to_string_lossy(),
                    e.flags
                );
            }
            Ok(Some(SyscallEvent::Exit(e))) => {
                println!("for ({}, {}) -> {}", e.pid >> 32, e.pid & 0xFFFFFFFF, e.ret);
            }
            Ok(None) => break,
            Err(_) => {}
        }
    }
    Ok(())
}
