use anyhow::Result;
use libc::{self, dirfd};
use once_cell::sync::Lazy;
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::CStr;
use std::path::{Component, PathBuf};
use std::sync::{Mutex, RwLock};
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

#[derive(Debug)]
pub enum SyscallEvent {
    Enter0(sys_enter_info0_t),
    Enter1(sys_enter_info1_t),
    Enter2(sys_enter_info2_t),
    Exit(sys_exit_info_t),
}

pub struct Context {
    cwd_map: HashMap<u64, PathBuf>,
    log: HashMap<u64, VecDeque<SyscallEvent>>,
    process_graph: HashMap<u64, u64>,
    dirfd_map: HashMap<(u64, i32), PathBuf>
}

impl Context {
    pub fn new() -> Context {
        Context {
            cwd_map: HashMap::new(),
            log: HashMap::new(),
            process_graph: HashMap::new(),
            dirfd_map: HashMap::new()
        }
    }

    pub fn update_log(&mut self, pid_tgid: u64, event: SyscallEvent) {
        self.log
            .entry(pid_tgid)
            .and_modify(|vd| vd.push_back(event))
            .or_insert(VecDeque::new());
    }

    pub fn dump_log(&mut self) {
        for (pid_tgid, log) in self.log.iter() {
            println!(
                "log for pid {} tgid {}:",
                pid_tgid & 0xFFFFFFFF,
                pid_tgid >> 32
            );
            for e in log.iter() {
                match e {
                    SyscallEvent::Enter0(e) => {
                        print!("{}(flags={})", e.syscall_nr, e.flags);
                    }
                    SyscallEvent::Enter1(e) => {
                        let cstr = unsafe { CStr::from_ptr(e.path.as_ptr()) };
                        print!(
                            "{}(fd={},path={},flags={})",
                            e.syscall_nr,
                            e.fd,
                            cstr.to_string_lossy(),
                            e.flags
                        );
                    }
                    SyscallEvent::Enter2(e) => {
                        let cstr = unsafe { CStr::from_ptr(e.path.as_ptr()) };
                        let cstr2 = unsafe { CStr::from_ptr(e.path2.as_ptr()) };
                        print!(
                            "{}(fd={},path={},fd2={},path2={},flags={})",
                            e.syscall_nr,
                            e.fd,
                            cstr.to_string_lossy(),
                            e.fd2,
                            cstr2.to_string_lossy(),
                            e.flags
                        );
                    }
                    SyscallEvent::Exit(e) => {
                        println!(" -> {}", e.ret);
                    }
                };
            }
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

    fn compute_closure(canon_path: PathBuf) -> Vec<PathBuf> {
        let mut v = Vec::new();
        let mut cur = canon_path;
        while let Some(p) = cur.parent() {
            v.push(p.to_path_buf());
            cur = p.to_path_buf();
        }
        v
    }
}

pub static CTXT: Lazy<Mutex<Context>> = Lazy::new(|| Mutex::new(Context::new()));
pub static SETS: Lazy<Mutex<RWSet>> = Lazy::new(|| Mutex::new(RWSet::new()));

enum SyscallInfo {
    Event0 {
        pid: u64,
        ret: i64,
        syscall_nr: i64,
        flags: u32,
    },
    Event1 {
        pid: u64,
        ret: i64,
        syscall_nr: i64,
        flags: u32,
        fd: i32,
        path: String,
    },
    Event2 {
        pid: u64,
        ret: i64,
        syscall_nr: i64,
        flags: u32,
        fd: i32,
        path: String,
        fd2: i32,
        path2: String,
    },
}

fn on_event_update_rw_sets(event: SyscallInfo) {
    match event {
        SyscallInfo::Event0 {
            pid,
            ret,
            syscall_nr,
            flags,
        } => match syscall_nr {
            libc::SYS_clone => {
                let mut ctxt = CTXT.lock().unwrap();
                let mut sets = SETS.lock().unwrap();
                parse_clone(&mut ctxt, &mut sets, pid, ret, syscall_nr, flags)
            }
            libc::SYS_inotify_add_watch => {}
            _ => {}
        },
        SyscallInfo::Event1 {
            pid,
            ret,
            syscall_nr,
            flags,
            fd,
            path,
        } => match syscall_nr {
            libc::SYS_openat => {
                let mut ctxt = CTXT.lock().unwrap();
                let mut sets = SETS.lock().unwrap();
                parse_openat(&mut ctxt, &mut sets, pid, ret, syscall_nr, flags, fd, &path)
            }

            // #[cfg(target_arch = "x86_64")]
            // libc::SYS_open => {
            //     let mut ctxt = CTXT.lock().unwrap();
            //     let mut sets = SETS.lock().unwrap();
            //     parse_open(&mut ctxt, &mut sets, pid, ret, syscall_nr, flags, fd, &path)
            // }
            libc::SYS_chdir => {
                let mut ctxt = CTXT.lock().unwrap();
                let mut sets = SETS.lock().unwrap();
                parse_chdir(&mut ctxt, &mut sets, pid, ret, syscall_nr, flags, fd, &path)
            }
            libc::SYS_symlinkat => {
                let mut ctxt = CTXT.lock().unwrap();
                let mut sets = SETS.lock().unwrap();
                parse_symlinkat(&mut ctxt, &mut sets, pid, ret, syscall_nr, flags, fd, &path)
            }
            // libc::SYS_symlink => {}
            // r path
            libc::SYS_execve => {
                let mut ctxt = CTXT.lock().unwrap();
                let mut sets = SETS.lock().unwrap();
                parse_r_first_path_e1(&mut ctxt, &mut sets, pid, ret, syscall_nr, flags, fd, &path)
            }
            libc::SYS_statfs => {
                let mut ctxt = CTXT.lock().unwrap();
                let mut sets = SETS.lock().unwrap();
                parse_r_first_path_e1(&mut ctxt, &mut sets, pid, ret, syscall_nr, flags, fd, &path)
            }
            libc::SYS_getxattr => {
                let mut ctxt = CTXT.lock().unwrap();
                let mut sets = SETS.lock().unwrap();
                parse_r_first_path_e1(&mut ctxt, &mut sets, pid, ret, syscall_nr, flags, fd, &path)
            }
            libc::SYS_lgetxattr => {
                let mut ctxt = CTXT.lock().unwrap();
                let mut sets = SETS.lock().unwrap();
                parse_r_first_path_e1(&mut ctxt, &mut sets, pid, ret, syscall_nr, flags, fd, &path)
            }
            // libc::SYS_stat => {}
            // libc::SYS_lstat => {}
            // libc::SYS_access => {}
            // libc::SYS_readlink => {}
            // w path
            libc::SYS_truncate => {
                let mut ctxt = CTXT.lock().unwrap();
                let mut sets = SETS.lock().unwrap();
                parse_w_first_path_e1(&mut ctxt, &mut sets, pid, ret, syscall_nr, flags, fd, &path)
            }
            libc::SYS_acct => {
                let mut ctxt = CTXT.lock().unwrap();
                let mut sets = SETS.lock().unwrap();
                parse_w_first_path_e1(&mut ctxt, &mut sets, pid, ret, syscall_nr, flags, fd, &path)
            }
            // libc::SYS_mkdir => {}
            // libc::SYS_rmdir => {}
            // libc::SYS_creat => {}
            // libc::SYS_chmod => {}
            // libc::SYS_chown => {}
            // libc::SYS_lchown => {}
            // libc::SYS_utime => {}
            // libc::SYS_utimes => {}
            // libc::SYS_mknod => {}
            // libc::SYS_unlink => {}
            // r fd path
            libc::SYS_newfstatat => {
                let mut ctxt = CTXT.lock().unwrap();
                let mut sets = SETS.lock().unwrap();
                parse_r_fd_path_e1(&mut ctxt, &mut sets, pid, ret, syscall_nr, flags, fd, &path)
            }
            libc::SYS_statx => {
                let mut ctxt = CTXT.lock().unwrap();
                let mut sets = SETS.lock().unwrap();
                parse_r_fd_path_e1(&mut ctxt, &mut sets, pid, ret, syscall_nr, flags, fd, &path)
            }
            libc::SYS_name_to_handle_at => {
                let mut ctxt = CTXT.lock().unwrap();
                let mut sets = SETS.lock().unwrap();
                parse_r_fd_path_e1(&mut ctxt, &mut sets, pid, ret, syscall_nr, flags, fd, &path)
            }
            libc::SYS_readlinkat => {
                let mut ctxt = CTXT.lock().unwrap();
                let mut sets = SETS.lock().unwrap();
                parse_r_fd_path_e1(&mut ctxt, &mut sets, pid, ret, syscall_nr, flags, fd, &path)
            }
            libc::SYS_faccessat => {
                let mut ctxt = CTXT.lock().unwrap();
                let mut sets = SETS.lock().unwrap();
                parse_r_fd_path_e1(&mut ctxt, &mut sets, pid, ret, syscall_nr, flags, fd, &path)
            }
            libc::SYS_faccessat2 => {
                let mut ctxt = CTXT.lock().unwrap();
                let mut sets = SETS.lock().unwrap();
                parse_r_fd_path_e1(&mut ctxt, &mut sets, pid, ret, syscall_nr, flags, fd, &path)
            }
            libc::SYS_execveat => {
                let mut ctxt = CTXT.lock().unwrap();
                let mut sets = SETS.lock().unwrap();
                parse_r_fd_path_e1(&mut ctxt, &mut sets, pid, ret, syscall_nr, flags, fd, &path)
            }
            // w fd path
            libc::SYS_linkat => {
                let mut ctxt = CTXT.lock().unwrap();
                let mut sets = SETS.lock().unwrap();
                parse_w_fd_path_e1(&mut ctxt, &mut sets, pid, ret, syscall_nr, flags, fd, &path)
            }
            libc::SYS_unlinkat => {
                let mut ctxt = CTXT.lock().unwrap();
                let mut sets = SETS.lock().unwrap();
                parse_r_fd_path_e1(&mut ctxt, &mut sets, pid, ret, syscall_nr, flags, fd, &path)
            }
            libc::SYS_utimensat => {
                let mut ctxt = CTXT.lock().unwrap();
                let mut sets = SETS.lock().unwrap();
                parse_r_fd_path_e1(&mut ctxt, &mut sets, pid, ret, syscall_nr, flags, fd, &path)
            }
            libc::SYS_mkdirat => {
                let mut ctxt = CTXT.lock().unwrap();
                let mut sets = SETS.lock().unwrap();
                parse_r_fd_path_e1(&mut ctxt, &mut sets, pid, ret, syscall_nr, flags, fd, &path)
            }
            libc::SYS_mknodat => {
                let mut ctxt = CTXT.lock().unwrap();
                let mut sets = SETS.lock().unwrap();
                parse_r_fd_path_e1(&mut ctxt, &mut sets, pid, ret, syscall_nr, flags, fd, &path)
            }
            libc::SYS_fchownat => {
                let mut ctxt = CTXT.lock().unwrap();
                let mut sets = SETS.lock().unwrap();
                parse_r_fd_path_e1(&mut ctxt, &mut sets, pid, ret, syscall_nr, flags, fd, &path)
            }
            libc::SYS_fchmodat => {
                let mut ctxt = CTXT.lock().unwrap();
                let mut sets = SETS.lock().unwrap();
                parse_r_fd_path_e1(&mut ctxt, &mut sets, pid, ret, syscall_nr, flags, fd, &path)
            }
            // libc::SYS_futimeat => {}
            _ => {}
        },
        SyscallInfo::Event2 {
            pid,
            ret,
            syscall_nr,
            flags,
            fd,
            path,
            fd2,
            path2,
        } => match syscall_nr {
            // libc::SYS_link => {}
            // libc::SYS_rename => {}
            libc::SYS_renameat => {
                let mut ctxt = CTXT.lock().unwrap();
                let mut sets = SETS.lock().unwrap();
                parse_renameat(&mut ctxt, &mut sets, pid, ret, syscall_nr, flags, fd, &path, fd2, &path2)
            }
            libc::SYS_renameat2 => {
                let mut ctxt = CTXT.lock().unwrap();
                let mut sets = SETS.lock().unwrap();
                parse_renameat(&mut ctxt, &mut sets, pid, ret, syscall_nr, flags, fd, &path, fd2, &path2)
            }
            _ => {}
        },
    }
}
fn is_absolute_path(path: &str) -> bool{
    !path.is_empty() && path.starts_with('/')
}

fn convert_absolute(ctxt: &Context, pid: u64, raw_path: &str, dirfd: Option<i32>) -> PathBuf {
    let binding = if is_absolute_path(raw_path) {
        PathBuf::from(raw_path)
    } else{
        let base = if let Some(fd) = dirfd {
            ctxt.dirfd_map.get(&(pid, fd))
                .expect("fd or pid not found in map")
                .clone()
        }   else{
            ctxt.cwd_map.get(&pid).expect("pid not found").clone()
        };
        base.join(raw_path)
    };
    let mut path_comps: Vec<Component>= Vec::new();

    for t in binding.components() {
        match t {
            Component::CurDir => {}
            Component::ParentDir => { 
                if let Some(last) = path_comps.last(){
                    if last.clone() != Component::RootDir{
                        path_comps.pop();
                    }
                } 
            },
            other => {path_comps.push(other);}

        };
    };

    let mut final_abs = PathBuf::new();
    for comp in path_comps.iter() {
        final_abs.push(comp.as_os_str());
    };
    final_abs

}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AccessKind {
    Read,
    Write,
}

fn parse_openat(ctxt: &mut Context, sets: &mut RWSet, pid: u64 ,ret: i64,syscall_nr: i64,flags: u32,fd: i32, path: &str) {
    
    let abs = convert_absolute(&ctxt, pid, &path, Some(fd));
    
    if ret >= 0 && (flags & libc::O_DIRECTORY as u32) != 0 {
        ctxt.dirfd_map.insert((pid, ret as i32), abs.clone());
    }

    let kind = if ret < 0 {
        AccessKind::Read
    } else if (flags & libc::O_RDONLY as u32) != 0 {
        AccessKind::Read
    } else {
        AccessKind::Write
    };
    insert_with_ancestors(sets, abs, kind);
}

fn parse_open(ctxt: &mut Context, sets: &mut RWSet, pid: u64 ,ret: i64,syscall_nr: i64,flags: u32,fd: i32, path: &str) {
    let abs = convert_absolute(&ctxt, pid, &path, None);
    if ret >= 0 && (flags & libc::O_DIRECTORY as u32) != 0 {
        ctxt.dirfd_map.insert((pid, ret as i32), abs.clone());
    }
    
    let kind = if ret < 0 {
        AccessKind::Read
    } else if (flags & libc::O_RDONLY as u32) != 0 {
        AccessKind::Read
    } else {
        AccessKind::Write
    };
    insert_with_ancestors(sets, abs, kind);
}

fn parse_chdir(ctxt: &mut Context, sets: &mut RWSet, pid: u64 ,ret: i64,syscall_nr: i64,flags: u32,fd: i32, path: &str) {
    let abs = convert_absolute(ctxt, pid, &path, None);
    if ret == 0{
        ctxt.cwd_map.insert(pid, abs.clone());
    }
    insert_with_ancestors(sets, abs, AccessKind::Read);
}

fn parse_clone(ctxt: &mut Context, sets: &mut RWSet, pid: u64 ,ret: i64,syscall_nr: i64,flags: u32) {
    if ret < 0{
        return;
    };
    if (flags & libc::CLONE_FS as u32) != 0 {
        ctxt.do_clone(pid, ret as u64)
    }
}

fn parse_symlinkat(ctxt: &mut Context, sets: &mut RWSet, pid: u64 ,ret: i64,syscall_nr: i64,flags: u32,fd: i32, path: &str) {
    let abs = convert_absolute(ctxt, pid, &path, Some(fd));
    let kind = if ret != 0 {
        AccessKind::Read
    } else{
        AccessKind::Write
    };

    insert_with_ancestors(sets, abs, kind);
}

fn parse_r_first_path_e1(ctxt: &mut Context, sets: &mut RWSet, pid: u64 ,ret: i64,syscall_nr: i64,flags: u32,fd: i32, path: &str) {
    if path.is_empty() {
        return;
    }
    let abs = convert_absolute(ctxt, pid, &path, None);

    insert_with_ancestors(sets, abs, AccessKind::Read);

}

fn parse_w_first_path_e1(ctxt: &mut Context, sets: &mut RWSet, pid: u64 ,ret: i64,syscall_nr: i64,flags: u32,fd: i32, path: &str) {
    if path.is_empty() {
        return;
    }

    let abs = convert_absolute(ctxt, pid, path, None);
    let kind = if ret == 0 {
        AccessKind::Write
    } else{
        AccessKind::Read
    };

    insert_with_ancestors(sets, abs, kind);

}

fn parse_r_fd_path_e1(ctxt: &mut Context, sets: &mut RWSet, pid: u64 ,ret: i64,syscall_nr: i64,flags: u32,fd: i32, path: &str) {
    if path.is_empty() {
        return;
    }

    let abs = convert_absolute(ctxt, pid, path, Some(fd));

    insert_with_ancestors(sets, abs, AccessKind::Read);
}

fn parse_w_fd_path_e1(ctxt: &mut Context, sets: &mut RWSet, pid: u64 ,ret: i64,syscall_nr: i64,flags: u32,fd: i32, path: &str) {
    if path.is_empty() {
        return;
    }

    let abs = convert_absolute(ctxt, pid, path, Some(fd));

    let kind = if ret != 0 {
        AccessKind::Read
    } else {
        AccessKind::Write
    };


    insert_with_ancestors(sets, abs, kind);
}

fn parse_renameat(ctxt: &mut Context, sets: &mut RWSet, pid: u64 ,ret: i64,syscall_nr: i64,flags: u32,fd: i32, path: &str, fd2: i32, path2: &str){
    let abs_path_1 = convert_absolute(ctxt, pid, path, Some(fd));
    let abs_path_2 = convert_absolute(ctxt, pid, path2, Some(fd2));

    insert_with_ancestors(sets, abs_path_1, AccessKind::Write);
    insert_with_ancestors(sets, abs_path_2, AccessKind::Write);



}

fn insert_with_ancestors(sets: &mut RWSet, p: PathBuf, kind: AccessKind) {
    match kind {
        AccessKind::Read => {
            sets.update_read_set(p.clone());
            for dir in RWSet::compute_closure(p) {
                sets.update_read_set(dir);
            }
        }
        AccessKind::Write => {
            sets.update_write_set(p.clone());
            for dir in RWSet::compute_closure(p) {
                sets.update_read_set(dir);
            }
        }
    }
}



pub fn event_stream_handler(rx: mpsc::Receiver<Option<SyscallEvent>>) -> Result<()> {
    loop {
        match rx.recv() {
            Ok(Some(SyscallEvent::Enter0(e))) => {
                let pid = e.pid as u64;
                let mut ctxt = CTXT.lock().unwrap();
                ctxt.update_log(pid, SyscallEvent::Enter0(e))
            }
            Ok(Some(SyscallEvent::Enter1(e))) => {
                let pid = e.pid as u64;
                let mut ctxt = CTXT.lock().unwrap();
                ctxt.update_log(pid, SyscallEvent::Enter1(e))
            }
            Ok(Some(SyscallEvent::Enter2(e))) => {
                let pid = e.pid as u64;
                let mut ctxt = CTXT.lock().unwrap();
                ctxt.update_log(pid, SyscallEvent::Enter2(e))
            }
            Ok(Some(SyscallEvent::Exit(exit_info))) => {
                let pid = exit_info.pid as u64;
                let mut ctxt = CTXT.lock().unwrap();
                ctxt.update_log(pid, SyscallEvent::Exit(exit_info));
                let event_queue = ctxt.log.get(&pid).unwrap();
                let len = event_queue.len();
                if len >= 2 {
                    let enter_event = &event_queue[len - 2];
                    match enter_event {
                        SyscallEvent::Enter0(e) => {
                            on_event_update_rw_sets(SyscallInfo::Event0 {
                                pid: e.pid as u64,
                                ret: exit_info.ret,
                                syscall_nr: e.syscall_nr,
                                flags: e.flags as u32,
                            });
                        }
                        SyscallEvent::Enter1(e) => {
                            let path_cstr = unsafe { CStr::from_ptr(e.path.as_ptr()) };

                            on_event_update_rw_sets(SyscallInfo::Event1 {
                                pid: e.pid as u64,
                                ret: exit_info.ret,
                                syscall_nr: e.syscall_nr,
                                flags: e.flags as u32,
                                fd: e.fd,
                                path: String::from_utf8_lossy(path_cstr.to_bytes()).to_string(),
                            });
                        }
                        SyscallEvent::Enter2(e) => {
                            let path_cstr = unsafe { CStr::from_ptr(e.path.as_ptr()) };
                            let path2_cstr = unsafe { CStr::from_ptr(e.path2.as_ptr()) };

                            on_event_update_rw_sets(SyscallInfo::Event2 {
                                pid: e.pid as u64,
                                ret: exit_info.ret,
                                syscall_nr: e.syscall_nr,
                                flags: e.flags as u32,
                                fd: e.fd,
                                path: String::from_utf8_lossy(path_cstr.to_bytes()).to_string(),
                                fd2: e.fd2,
                                path2: String::from_utf8_lossy(path2_cstr.to_bytes()).to_string(),
                            });
                        }
                        _ => {}
                    };
                }
            }
            Ok(None) => break,
            Err(_) => {}
        }
    }
    Ok(())
}
