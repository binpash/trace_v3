use anyhow::Result;
use libc::{self, dirfd};
use once_cell::sync::Lazy;
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::CStr;
use std::path::{Component, PathBuf};
use std::sync::mpsc;
use std::sync::{Mutex, RwLock};
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
pub struct Logs {
    log: HashMap<u64, VecDeque<SyscallEvent>>,
}

impl Logs {
    pub fn new() -> Logs {
        Logs {
            log: HashMap::new(),
        }
    }
    pub fn update_log(&mut self, pid_tgid: u64, event: SyscallEvent) {
        self.log
            .entry(pid_tgid)
            .or_insert_with(|| VecDeque::new())
            .push_back(event);
    }

    pub fn dump_log(&mut self) {
        let mut sorted_logs: Vec<_> = self
            .log
            .iter()
            .map(|(pid_tgid, logs)| (pid_tgid & 0xFFFFFFFF, pid_tgid >> 32, logs))
            .collect();

        sorted_logs.sort_by(|(pid1, _, _), (pid2, _, _)| pid1.cmp(pid2));

        for (pid, tgid, log) in sorted_logs {
            println!("log for pid {} tgid {}:", pid, tgid);
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
}

pub struct Context {
    cwd_map: HashMap<u64, PathBuf>,
    process_graph: HashMap<u64, u64>,
    dirfd_map: HashMap<(u64, i32), PathBuf>,
    openfds_map: HashMap<(i32, i32), PathBuf>,
}

impl Context {
    pub fn new() -> Context {
        Context {
            cwd_map: HashMap::new(),
            process_graph: HashMap::new(),
            dirfd_map: HashMap::new(),
            openfds_map: HashMap::new(),
        }
    }
    pub fn init_pid(&mut self, pid: u64, cwd: PathBuf) {
        self.cwd_map.insert(pid, cwd);
    }

    pub fn do_clone(&mut self, parent_pid_tgid: u64, child_pid_tgid: u64) -> () {
        self.process_graph.insert(child_pid_tgid, parent_pid_tgid);
        let parent_cwd = self.cwd_map.get(&parent_pid_tgid).unwrap();
        self.cwd_map.insert(child_pid_tgid, parent_cwd.clone());
        let new_pid_fds: Vec<_> = self
            .openfds_map
            .iter()
            .filter(|((pid, _), _)| *pid == (parent_pid_tgid & 0xFFFFFFFF) as i32)
            .map(|(&key, path)| (key, path.clone()))
            .collect();
        for ((_old_pid, fd), path) in new_pid_fds {
            self.map_fds((child_pid_tgid & 0xFFFFFFFF) as i32, fd, path.to_owned())
        }
    }

    pub fn map_fds(&mut self, pid: i32, fd: i32, path: PathBuf) {
        self.openfds_map.insert((pid, fd), path);
    }

    pub fn get_path_from_fd(&self, pid: i32, fd: i32) -> Option<PathBuf> {
        self.openfds_map.get(&(pid, fd)).map(|path| path.clone())
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

    pub fn dump_sets(&mut self) {
        let rset = &self.read_set;
        let wset = &self.write_set;
        println!("Read set");
        let mut r = Vec::from_iter(rset);
        r.sort();
        for p in r {
            println!("{p:?}")
        }

        println!("Write set");
        let mut w = Vec::from_iter(wset);
        w.sort();
        for p in w {
            println!("{p:?}")
        }
    }
}

pub static CTXT: Lazy<Mutex<Context>> = Lazy::new(|| Mutex::new(Context::new()));
pub static SETS: Lazy<Mutex<RWSet>> = Lazy::new(|| Mutex::new(RWSet::new()));
pub static LOGS: Lazy<Mutex<Logs>> = Lazy::new(|| Mutex::new(Logs::new()));

enum SyscallInfo {
    Event0 {
        pid_tgid: u64,
        ret: i64,
        syscall_nr: i64,
        flags: u32,
    },
    Event1 {
        pid_tgid: u64,
        ret: i64,
        syscall_nr: i64,
        flags: u32,
        fd: i32,
        path: String,
    },
    Event2 {
        pid_tgid: u64,
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
    let mut ctxt = CTXT.lock().unwrap();
    let mut sets = SETS.lock().unwrap();
    match event {
        SyscallInfo::Event0 {
            pid_tgid,
            ret,
            syscall_nr,
            flags,
        } => match syscall_nr {
            libc::SYS_clone => parse_clone(&mut ctxt, &mut sets, pid_tgid, ret, syscall_nr, flags),
            _ => {}
        },
        SyscallInfo::Event1 {
            pid_tgid,
            ret,
            syscall_nr,
            flags,
            fd,
            path,
        } => match syscall_nr {
            libc::SYS_dup => parse_dup(
                &mut ctxt, &mut sets, pid_tgid, ret, syscall_nr, flags, fd, &path,
            ),
            libc::SYS_inotify_add_watch => parse_SYS_inotify_add_watch(
                &mut ctxt, &mut sets, pid_tgid, ret, syscall_nr, flags, fd, &path,
            ),
            libc::SYS_openat | libc::SYS_openat2 => parse_openat(
                &mut ctxt, &mut sets, pid_tgid, ret, syscall_nr, flags, fd, &path,
            ),
            // #[cfg(target_arch = "x86_64")]
            // libc::SYS_open => {
            //     let mut ctxt = CTXT.lock().unwrap();
            //     let mut sets = SETS.lock().unwrap();
            //     parse_open(
            //         &mut ctxt, &mut sets, pid_tgid, ret, syscall_nr, flags, fd, &path,
            //     )
            // }
            libc::SYS_chdir => parse_chdir(
                &mut ctxt, &mut sets, pid_tgid, ret, syscall_nr, flags, fd, &path,
            ),
            libc::SYS_symlinkat => parse_symlinkat(
                &mut ctxt, &mut sets, pid_tgid, ret, syscall_nr, flags, fd, &path,
            ),
            // libc::SYS_symlink => {}
            // r path
            libc::SYS_execve | libc::SYS_statfs | libc::SYS_getxattr | libc::SYS_lgetxattr => {
                parse_r_first_path_e1(
                    &mut ctxt, &mut sets, pid_tgid, ret, syscall_nr, flags, fd, &path,
                )
            }
            // libc::SYS_stat => {}
            // libc::SYS_lstat => {}
            // libc::SYS_access => {}
            // libc::SYS_readlink => {}
            // w path
            libc::SYS_truncate | libc::SYS_acct => parse_w_first_path_e1(
                &mut ctxt, &mut sets, pid_tgid, ret, syscall_nr, flags, fd, &path,
            ),
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
            libc::SYS_newfstatat
            | libc::SYS_statx
            | libc::SYS_name_to_handle_at
            | libc::SYS_readlinkat
            | libc::SYS_faccessat
            | libc::SYS_faccessat2
            | libc::SYS_execveat => parse_r_fd_path_e1(
                &mut ctxt, &mut sets, pid_tgid, ret, syscall_nr, flags, fd, &path,
            ),
            // w fd path
            libc::SYS_linkat
            | libc::SYS_unlinkat
            | libc::SYS_utimensat
            | libc::SYS_mkdirat
            | libc::SYS_mknodat
            | libc::SYS_fchownat
            | libc::SYS_fchmodat => parse_w_fd_path_e1(
                &mut ctxt, &mut sets, pid_tgid, ret, syscall_nr, flags, fd, &path,
            ),
            // libc::SYS_futimeat => {}
            _ => {}
        },
        SyscallInfo::Event2 {
            pid_tgid,
            ret,
            syscall_nr,
            flags,
            fd,
            path,
            fd2,
            path2,
        } => match syscall_nr {
            libc::SYS_dup3 => parse_dup23(
                &mut ctxt, &mut sets, pid_tgid, ret, syscall_nr, flags, fd, &path, fd2, &path2,
            ),
            // libc::SYS_link => {}
            // libc::SYS_rename => {}
            libc::SYS_renameat | libc::SYS_renameat2 => parse_renameat(
                &mut ctxt, &mut sets, pid_tgid, ret, syscall_nr, flags, fd, &path, fd2, &path2,
            ),
            libc::SYS_pipe2 => parse_pipe2(
                &mut ctxt, &mut sets, pid_tgid, ret, syscall_nr, flags, fd, &path, fd2, &path2,
            ),
            _ => {}
        },
    }
}

fn is_absolute_path(path: &str) -> bool {
    !path.is_empty() && path.starts_with('/')
}

fn convert_absolute(ctxt: &Context, pid_tgid: u64, raw_path: &str, dirfd: Option<i32>) -> PathBuf {
    let binding = if is_absolute_path(raw_path) {
        PathBuf::from(raw_path)
    } else {
        let base = if let Some(fd) = dirfd {
            if fd == libc::AT_FDCWD {
                ctxt.cwd_map
                    .get(&pid_tgid)
                    .expect("pid_tgid not found bc pid_tgid not in cwd")
                    .clone()
            } else {
                ctxt.dirfd_map
                    .get(&(pid_tgid, fd))
                    .expect("fd or pid_tgid not found in map")
                    .clone()
            }
        } else {
            ctxt.cwd_map
                .get(&pid_tgid)
                .expect("pid_tgid not found")
                .clone()
        };
        base.join(raw_path)
    };
    let mut path_comps: Vec<Component> = Vec::new();

    for t in binding.components() {
        match t {
            Component::CurDir => {}
            Component::ParentDir => {
                if let Some(last) = path_comps.last() {
                    if last.clone() != Component::RootDir {
                        path_comps.pop();
                    }
                }
            }
            other => {
                path_comps.push(other);
            }
        };
    }

    let mut final_abs = PathBuf::new();
    for comp in path_comps.iter() {
        final_abs.push(comp.as_os_str());
    }
    final_abs
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AccessKind {
    Read,
    Write,
}

fn parse_dup(
    ctxt: &mut Context,
    _sets: &mut RWSet,
    pid_tgid: u64,
    ret: i64,
    _syscall_nr: i64,
    _flags: u32,
    fd: i32,
    _path: &str,
) {
    if ret < 0 {
        return;
    }

    let new_fd = match i32::try_from(ret) {
        Ok(x) => x,
        Err(_) => return,
    };

    let pid: i32 = (pid_tgid & 0xFFFF_FFFF) as i32;

    if let Some(p) = ctxt.get_path_from_fd(pid, fd) {
        ctxt.map_fds(pid, fd, p.clone());
        ctxt.map_fds(pid, new_fd, p);
    }
}

fn parse_dup23(
    ctxt: &mut Context,
    sets: &mut RWSet,
    pid_tgid: u64,
    ret: i64,
    syscall_nr: i64,
    flags: u32,
    fd: i32,
    path: &str,
    fd2: i32,
    path2: &str,
) {
    let pid = (pid_tgid & 0xFFFFFFFF) as i32;

    if ret >= 0 {
        let new_map = ctxt.get_path_from_fd(pid, fd);
        if let Some(valid_path) = new_map {
            ctxt.map_fds(pid, fd2, valid_path);
        }
    }
}

fn parse_pipe2(
    ctxt: &mut Context,
    sets: &mut RWSet,
    pid_tgid: u64,
    ret: i64,
    syscall_nr: i64,
    flags: u32,
    fd: i32,
    path: &str,
    fd2: i32,
    path2: &str,
) {
    let path = convert_absolute(ctxt, pid_tgid, path, None);
    let pid = (pid_tgid & 0xFFFFFFFF) as i32;
    println!("{pid}");

    ctxt.map_fds(pid, fd, path.clone());
    ctxt.map_fds(pid, fd2, path.clone());
    insert_with_ancestors(sets, path.clone(), AccessKind::Read);
    insert_with_ancestors(sets, path, AccessKind::Write);

}

fn parse_SYS_inotify_add_watch(
    ctxt: &mut Context,
    sets: &mut RWSet,
    pid_tgid: u64,
    ret: i64,
    syscall_nr: i64,
    flags: u32,
    fd: i32,
    path: &str,
) {
    if path.is_empty() {
        return;
    }
    let abs = convert_absolute(ctxt, pid_tgid, path, None);

    insert_with_ancestors(sets, abs, AccessKind::Read);
}

// fn parse_openat(
//     ctxt: &mut Context,
//     sets: &mut RWSet,
//     pid: u64,
//     ret: i64,
//     syscall_nr: i64,
//     flags: u32,
//     fd: i32,
//     path: &str,
// ) {
//     let abs = convert_absolute(&ctxt, pid, &path, Some(fd));
//     if ret >= 0 {
//         let new_fd = ret as i32;
//         ctxt.map_fds((pid & 0xFFFFFFFF) as i32, new_fd, abs.clone());

//         if (flags & libc::O_DIRECTORY as u32) != 0 {
//             ctxt.dirfd_map.insert((pid, new_fd), abs.clone());
//         }
//     }

//     let kind = if ret < 0 {
//         AccessKind::Read
//     } else if (flags & libc::O_RDONLY as u32) != 0 {
//         AccessKind::Read
//     } else {
//         AccessKind::Write
//     };
//     insert_with_ancestors(sets, abs, kind);
// }

fn parse_openat(
    ctxt: &mut Context,
    sets: &mut RWSet,
    pid_tgid: u64,
    ret: i64,
    syscall_nr: i64,
    flags: u32,
    fd: i32,
    path: &str,
) {
    let abs = convert_absolute(&ctxt, pid_tgid, &path, Some(fd));
    if ret >= 0 {
        let new_fd = ret as i32;
        ctxt.map_fds((pid_tgid & 0xFFFFFFFF) as i32, new_fd, abs.clone());

        if (flags & libc::O_DIRECTORY as u32) != 0 {
            ctxt.dirfd_map.insert((pid_tgid, new_fd), abs.clone());
        }
    }

    if ret < 0 {
        // Failed open is always a read attempt
        insert_with_ancestors(sets, abs, AccessKind::Read);
    } else {
        // Check the access mode (lower 2 bits of flags)
        let access_mode = (flags & libc::O_ACCMODE as u32) as i32;

        match access_mode {
            libc::O_RDONLY => {
                insert_with_ancestors(sets, abs, AccessKind::Read);
            }
            libc::O_WRONLY => {
                insert_with_ancestors(sets, abs, AccessKind::Write);
            }
            libc::O_RDWR => {
                // File is opened for both reading and writing
                insert_with_ancestors(sets, abs.clone(), AccessKind::Read);
                insert_with_ancestors(sets, abs, AccessKind::Write);
            }
            _ => {
                // Shouldn't happen, but default to read
                insert_with_ancestors(sets, abs, AccessKind::Read);
            }
        }
    }
}

fn parse_open(
    ctxt: &mut Context,
    sets: &mut RWSet,
    pid_tgid: u64,
    ret: i64,
    syscall_nr: i64,
    flags: u32,
    fd: i32,
    path: &str,
) {
    let abs = convert_absolute(&ctxt, pid_tgid, &path, None);
    if ret >= 0 && (flags & libc::O_DIRECTORY as u32) != 0 {
        ctxt.dirfd_map.insert((pid_tgid, ret as i32), abs.clone());
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

fn parse_chdir(
    ctxt: &mut Context,
    sets: &mut RWSet,
    pid_tgid: u64,
    ret: i64,
    syscall_nr: i64,
    flags: u32,
    fd: i32,
    path: &str,
) {
    let abs = convert_absolute(ctxt, pid_tgid, &path, None);
    if ret == 0 {
        ctxt.cwd_map.insert(pid_tgid, abs.clone());
    }
    insert_with_ancestors(sets, abs, AccessKind::Read);
}

fn parse_clone(
    ctxt: &mut Context,
    sets: &mut RWSet,
    pid_tgid: u64,
    ret: i64,
    syscall_nr: i64,
    flags: u32,
) {
    if ret < 0 {
        return;
    };
    let pid = (pid_tgid & 0xFFFFFFFF) as i32;
    let r = ret as i32;
    ctxt.do_clone(pid_tgid, ret as u64)
}

fn parse_symlinkat(
    ctxt: &mut Context,
    sets: &mut RWSet,
    pid_tgid: u64,
    ret: i64,
    syscall_nr: i64,
    flags: u32,
    fd: i32,
    path: &str,
) {
    let abs = convert_absolute(ctxt, pid_tgid, &path, Some(fd));
    let kind = if ret != 0 {
        AccessKind::Read
    } else {
        AccessKind::Write
    };

    insert_with_ancestors(sets, abs, kind);
}

fn parse_r_first_path_e1(
    ctxt: &mut Context,
    sets: &mut RWSet,
    pid_tgid: u64,
    ret: i64,
    syscall_nr: i64,
    flags: u32,
    fd: i32,
    path: &str,
) {
    if path.is_empty() {
        return;
    }
    let abs = convert_absolute(ctxt, pid_tgid, &path, None);

    insert_with_ancestors(sets, abs, AccessKind::Read);
}

fn parse_w_first_path_e1(
    ctxt: &mut Context,
    sets: &mut RWSet,
    pid_tgid: u64,
    ret: i64,
    syscall_nr: i64,
    flags: u32,
    fd: i32,
    path: &str,
) {
    if path.is_empty() {
        return;
    }

    let abs = convert_absolute(ctxt, pid_tgid, path, None);
    let kind = if ret == 0 {
        AccessKind::Write
    } else {
        AccessKind::Read
    };

    insert_with_ancestors(sets, abs, kind);
}

fn parse_r_fd_path_e1(
    ctxt: &mut Context,
    sets: &mut RWSet,
    pid_tgid: u64,
    ret: i64,
    syscall_nr: i64,
    flags: u32,
    fd: i32,
    path: &str,
) {
    if path.is_empty() {
        return;
    }

    let abs = convert_absolute(ctxt, pid_tgid, path, Some(fd));

    insert_with_ancestors(sets, abs, AccessKind::Read);
}

fn parse_w_fd_path_e1(
    ctxt: &mut Context,
    sets: &mut RWSet,
    pid_tgid: u64,
    ret: i64,
    syscall_nr: i64,
    flags: u32,
    fd: i32,
    path: &str,
) {
    if path.is_empty() {
        return;
    }

    let abs = convert_absolute(ctxt, pid_tgid, path, Some(fd));

    let kind = if ret != 0 {
        AccessKind::Read
    } else {
        AccessKind::Write
    };

    insert_with_ancestors(sets, abs, kind);
}

fn parse_renameat(
    ctxt: &mut Context,
    sets: &mut RWSet,
    pid_tgid: u64,
    ret: i64,
    syscall_nr: i64,
    flags: u32,
    fd: i32,
    path: &str,
    fd2: i32,
    path2: &str,
) {
    let abs_path_1 = convert_absolute(ctxt, pid_tgid, path, Some(fd));
    let abs_path_2 = convert_absolute(ctxt, pid_tgid, path2, Some(fd2));

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
                let pid_tgid = e.pid_tgid as u64;
                let mut logs = LOGS.lock().unwrap();
                logs.update_log(pid_tgid, SyscallEvent::Enter0(e))
            }
            Ok(Some(SyscallEvent::Enter1(mut e))) => {
                let pid_tgid = e.pid_tgid as u64;
                {
                    let ctxt = CTXT.lock().unwrap();
                    if libc::SYS_dup == e.syscall_nr {
                        let pid = (e.pid_tgid & 0xFFFFFFFF) as i32;
                        if let Some(p) = ctxt.get_path_from_fd(pid, e.fd) {
                            let path = p.to_str().unwrap().as_bytes();
                            let len = e.path.len().min(path.len());
                            e.path[..len].copy_from_slice(path);
                        }
                    }
                }
                let mut logs = LOGS.lock().unwrap();
                logs.update_log(pid_tgid, SyscallEvent::Enter1(e))
            }
            Ok(Some(SyscallEvent::Enter2(mut e))) => {
                let pid_tgid = e.pid_tgid as u64;
                {
                    let ctxt = CTXT.lock().unwrap();
                    if libc::SYS_dup3 == e.syscall_nr {
                        let pid = (e.pid_tgid & 0xFFFFFFFF) as i32;
                        if let Some(p) = ctxt.get_path_from_fd(pid, e.fd) {
                            let path = p.to_str().unwrap().as_bytes();
                            let len = e.path.len().min(path.len());
                            e.path[..len].copy_from_slice(path);
                        }
                    }
                }
                let mut logs = LOGS.lock().unwrap();
                logs.update_log(pid_tgid, SyscallEvent::Enter2(e))
            }
            Ok(Some(SyscallEvent::Exit(exit_info))) => {
                let pid_tgid = exit_info.pid_tgid as u64;
                let mut logs = LOGS.lock().unwrap();
                logs.update_log(pid_tgid, SyscallEvent::Exit(exit_info));
                let event_queue = logs.log.get(&pid_tgid).unwrap();
                let len = event_queue.len();
                if len >= 2 {
                    let enter_event = &event_queue[len - 2];
                    match enter_event {
                        SyscallEvent::Enter0(e) => {
                            on_event_update_rw_sets(SyscallInfo::Event0 {
                                pid_tgid: e.pid_tgid as u64,
                                ret: exit_info.ret,
                                syscall_nr: e.syscall_nr,
                                flags: e.flags as u32,
                            });
                        }
                        SyscallEvent::Enter1(e) => {
                            let path_cstr = unsafe { CStr::from_ptr(e.path.as_ptr()) };

                            on_event_update_rw_sets(SyscallInfo::Event1 {
                                pid_tgid: e.pid_tgid as u64,
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
                                pid_tgid: e.pid_tgid as u64,
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
