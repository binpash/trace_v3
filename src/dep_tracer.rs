use anyhow::Result;
use libc;
use std::collections::{HashMap, HashSet};
use std::ffi::CStr;
use std::path::PathBuf;
use std::sync::mpsc;
use trace_v3::*;

#[cfg(target_arch = "x86_64")]
pub fn individually_handled_syscall_map() -> HashMap<i64, &'static str> {
    let mut m = HashMap::new();

    m.insert(libc::SYS_openat, "openat");
    m.insert(libc::SYS_open, "open");
    m.insert(libc::SYS_chdir, "chdir");
    m.insert(libc::SYS_clone, "clone");
    m.insert(libc::SYS_rename, "rename");
    m.insert(libc::SYS_symlinkat, "symlinkat");
    m.insert(libc::SYS_link, "link");
    m
}
#[cfg(target_arch = "aarch64")]
pub fn individually_handled_syscall_map() -> HashMap<i64, &'static str> {
    let mut m = HashMap::new();

    m.insert(libc::SYS_openat, "openat");
    m.insert(libc::SYS_chdir, "chdir");
    m.insert(libc::SYS_clone, "clone");
    m.insert(libc::SYS_symlinkat, "symlinkat");
    m
}
#[cfg(target_arch = "x86_64")]
pub fn r_path_syscall_map() -> HashMap<i64, &'static str> {
    let mut m = HashMap::new();

    m.insert(libc::SYS_execve, "execve");
    m.insert(libc::SYS_stat, "stat");
    m.insert(libc::SYS_lstat, "lstat");
    m.insert(libc::SYS_access, "access");
    m.insert(libc::SYS_statfs, "statfs");
    m.insert(libc::SYS_readlink, "readlink");
    m.insert(libc::SYS_execve, "execve");
    m.insert(libc::SYS_getxattr, "getxattr");
    m.insert(libc::SYS_lgetxattr, "lgetxattr");
    m.insert(libc::SYS_llistxattr, "llistxattr");
    m
}
#[cfg(target_arch = "aarch64")]
pub fn r_path_syscall_map() -> HashMap<i64, &'static str> {
    let mut m = HashMap::new();

    m.insert(libc::SYS_execve, "execve");
    m.insert(libc::SYS_statfs, "statfs");
    m.insert(libc::SYS_execve, "execve");
    m.insert(libc::SYS_getxattr, "getxattr");
    m.insert(libc::SYS_lgetxattr, "lgetxattr");
    m.insert(libc::SYS_llistxattr, "llistxattr");
    m
}
#[cfg(target_arch = "x86_64")]
pub fn w_path_syscall_map() -> HashMap<i64, &'static str> {
    let mut m = HashMap::new();

    m.insert(libc::SYS_mkdir, "mkdir");
    m.insert(libc::SYS_rmdir, "rmdir");
    m.insert(libc::SYS_truncate, "truncate");
    m.insert(libc::SYS_creat, "creat");
    m.insert(libc::SYS_chmod, "chmod");
    m.insert(libc::SYS_chown, "chown");
    m.insert(libc::SYS_lchown, "lchown");
    m.insert(libc::SYS_utime, "utime");
    m.insert(libc::SYS_mknod, "mknod");
    m.insert(libc::SYS_utimes, "utimes");
    m.insert(libc::SYS_acct, "acct");
    m.insert(libc::SYS_unlink, "unlink");
    m.insert(libc::SYS_setxattr, "setxattr");
    m.insert(libc::SYS_removexattr, "removexattr");
    m
}
#[cfg(target_arch = "aarch64")]
pub fn w_path_syscall_map() -> HashMap<i64, &'static str> {
    let mut m = HashMap::new();

    m.insert(libc::SYS_truncate, "truncate");
    m.insert(libc::SYS_acct, "acct");
    m.insert(libc::SYS_setxattr, "setxattr");
    m.insert(libc::SYS_removexattr, "removexattr");
    m
}
#[cfg(target_arch = "x86_64")]
pub fn r_fd_path_syscall_map() -> HashMap<i64, &'static str> {
    let mut m = HashMap::new();

    m.insert(libc::SYS_fstatat, "fstatat");
    m.insert(libc::SYS_newfstatat, "newfstatat");
    m.insert(libc::SYS_statx, "statx");
    m.insert(libc::SYS_name_to_handle_at, "name_to_handle_at");
    m.insert(libc::SYS_readlinkat, "readlinkat");
    m.insert(libc::SYS_faccessat, "faccessat");
    m.insert(libc::SYS_execveat, "execveat");
    m.insert(libc::SYS_faccessat2, "faccessat2");
    m
}
#[cfg(target_arch = "aarch64")]
pub fn r_fd_path_syscall_map() -> HashMap<i64, &'static str> {
    let mut m = HashMap::new();

    m.insert(libc::SYS_newfstatat, "newfstatat");
    m.insert(libc::SYS_statx, "statx");
    m.insert(libc::SYS_name_to_handle_at, "name_to_handle_at");
    m.insert(libc::SYS_readlinkat, "readlinkat");
    m.insert(libc::SYS_faccessat, "faccessat");
    m.insert(libc::SYS_execveat, "execveat");
    m.insert(libc::SYS_faccessat2, "faccessat2");
    m
}
#[cfg(target_arch = "x86_64")]
pub fn w_fd_path_syscall_map() -> HashMap<i64, &'static str> {
    let mut m = HashMap::new();

    m.insert(libc::SYS_unlinkat, "unlinkat");
    m.insert(libc::SYS_utimensat, "utimensat");
    m.insert(libc::SYS_mkdirat, "mkdirat");
    m.insert(libc::SYS_mknodat, "mknodat");
    m.insert(libc::SYS_fchownat, "fchownat");
    m.insert(libc::SYS_futimeat, "futimeat");
    m.insert(libc::SYS_linkat, "linkat");
    m.insert(libc::SYS_fchmodat, "fchmodat");
    m
}
#[cfg(target_arch = "aarch64")]
pub fn w_fd_path_syscall_map() -> HashMap<i64, &'static str> {
    let mut m = HashMap::new();

    m.insert(libc::SYS_unlinkat, "unlinkat");
    m.insert(libc::SYS_utimensat, "utimensat");
    m.insert(libc::SYS_mkdirat, "mkdirat");
    m.insert(libc::SYS_mknodat, "mknodat");
    m.insert(libc::SYS_fchownat, "fchownat");
    m.insert(libc::SYS_linkat, "linkat");
    m.insert(libc::SYS_fchmodat, "fchmodat");
    m
}

pub enum SyscallEvent {
    Enter0(sys_enter_info0_t),
    Enter1(sys_enter_info1_t),
    Enter2(sys_enter_info2_t),
    Exit(sys_exit_info_t),
}

pub struct Context {
    cwd_map: HashMap<u64, PathBuf>,
    log: HashMap<u64, Vec<SyscallEvent>>,
    process_graph: HashMap<u64, u64>,
}

impl Context {
    pub fn new() -> Context {
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

pub struct RWSet {
    read_set: HashSet<PathBuf>,
    write_set: HashSet<PathBuf>,
}
impl RWSet {
    pub fn new() -> RWSet {
        RWSet {
            read_set: HashSet::new(),
            write_set: HashSet::new(),
        }
    }

    pub fn update_read_set(&mut self, path: PathBuf) {
        self.read_set.insert(path);
    }
    pub fn update_write_set(&mut self, path: PathBuf) {
        self.write_set.insert(path);
    }
}

// fn handle()

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
