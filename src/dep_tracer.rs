use anyhow::Result;
use libc::{self, dirfd};
use nix::sys;
use once_cell::sync::Lazy;
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::CStr;
use std::path::{Component, PathBuf};
use std::sync::mpsc;
use std::sync::{Mutex, RwLock};
use trace_v3::*;
use syscallnrs::{syscall_of_nr};

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

#[inline(always)]
pub fn upid_of(pid_tgid: u64) -> u32 {
    // NOTE: userspace pid = kernel tgid
    (pid_tgid >> 32) as u32
}

#[inline(always)]
pub fn utid_of(pid_tgid: u64) -> u32 {
    (pid_tgid & 0xFFFFFFFF) as u32
}

#[derive(Debug)]
pub enum SyscallEvent {
    Enter0(sys_enter_info0_t),
    Enter1(sys_enter_info1_t),
    Enter2(sys_enter_info2_t),
    EnterFcntl(sys_enter_fcntl_info_t),
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
    pub fn size(&self) {
        for (pid_tgid, vec) in &self.log{
            println!("{pid_tgid}");
            let a = vec.len();
            println!("{a}");
        };
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
            .map(|(pid_tgid, logs)| (upid_of(*pid_tgid), utid_of(*pid_tgid), logs))
            .collect();

        sorted_logs.sort_by(|(pid1, _, _), (pid2, _, _)| pid1.cmp(pid2));

        for (pid, tid, log) in sorted_logs {
            println!("log for pid {} tid {}:", pid, tid);
            for e in log.iter() {
                match e {
                    SyscallEvent::Enter0(e) => {
                        print!("{}(flags={})", 
                            match syscall_of_nr(e.syscall_nr as u64) {
                                Some(syscall) => syscall,
                                None => "Syscall not found"
                            },
                            e.flags
                        );
                    }
                    SyscallEvent::Enter1(e) => {
                        let cstr = unsafe { CStr::from_ptr(e.path.as_ptr()) };
                        print!(
                            "{}(fd={},path={},flags={})",
                            match syscall_of_nr(e.syscall_nr as u64) {
                                Some(syscall) => syscall,
                                None => "Syscall not found"
                            },
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
                            match syscall_of_nr(e.syscall_nr as u64) {
                                Some(syscall) => syscall,
                                None => "Syscall not found"
                            },
                            e.fd,
                            cstr.to_string_lossy(),
                            e.fd2,
                            cstr2.to_string_lossy(),
                            e.flags
                        );
                    }
                    SyscallEvent::EnterFcntl(e) => {
                        print!("{}(fd={},cmd={},arg={})", 
                            match syscall_of_nr(e.syscall_nr as u64) {
                                Some(syscall) => syscall,
                                None => "Syscall not found"
                            }, 
                            e.fd,
                            e.cmd, 
                            e.arg
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

#[derive(Clone, Debug)]
struct OpenFile {
    ref_cnt: u32,
    status_flags: u32,
    path: PathBuf,
}

#[derive(Debug)]
struct OpenFileTable {
    table: HashMap<u32, OpenFile>,
    ctr: u32,
}

impl OpenFileTable {
    pub fn new() -> OpenFileTable {
        OpenFileTable {
            table: HashMap::new(),
            ctr: 0,
        }
    }

    #[inline]
    pub fn get_path(&self, file: u32) -> Option<&OpenFile> {
        self.table.get(&file)
    }

    pub fn increment_ref_count(&mut self, file: u32) {
        if let Some(file) = self.table.get_mut(&file) {
            file.ref_cnt += 1
        } else {
        }
    }

    pub fn open_file(&mut self, status_flags: u32, path: PathBuf) -> u32 {
        while self.table.contains_key(&self.ctr) {
            self.ctr += 1;
        }
        self.table.insert(
            self.ctr,
            OpenFile {
                ref_cnt: 1,
                status_flags,
                path,
            },
        );
        let file = self.ctr;
        self.ctr += 1;
        file
    }

    pub fn close_file(&mut self, file: u32) {
        let mut cnt = 0;
        if let Some(file) = self.table.get_mut(&file) {
            file.ref_cnt -= 1;
            cnt = file.ref_cnt;
        } else {
        }
        if cnt == 0 {
            self.table.remove(&file);
            self.ctr = file;
        }
    }

    pub fn get_flags(&mut self, file: u32) -> u32 {
        let open_file = self
            .table
            .get(&file)
            .expect(format!("expected open file {file} to retrieve status flags").as_str());

        open_file.status_flags
    }

    pub fn set_flags(&mut self, file: u32, status_flags: u32) {
        let open_file = self
            .table
            .get_mut(&file)
            .expect(format!("expected open file {file} to modify status flags").as_str());

        open_file.status_flags = status_flags;
    }
}

#[derive(Clone, Debug)]
struct FileDesc {
    fd_flags: u32,
    open_file: u32,
}

pub struct Context {
    cwd_map: HashMap<u64, PathBuf>,
    process_graph: HashMap<u64, u64>,
    open_files: OpenFileTable,
    fd_tables: HashMap<u32, HashMap<i32, FileDesc>>,
}

impl Context {
    pub fn new() -> Context {
        Context {
            cwd_map: HashMap::new(),
            process_graph: HashMap::new(),
            open_files: OpenFileTable::new(),
            fd_tables: HashMap::new(),
        }
    }

    pub fn init_pid(&mut self, pid_tgid: u64, cwd: PathBuf) {
        self.cwd_map.insert(pid_tgid, cwd);
        self.fd_tables.insert(upid_of(pid_tgid), HashMap::new());
    }

    pub fn do_clone(&mut self, parent_pid_tgid: u64, child_pid_tgid: u64) {
        self.process_graph.insert(child_pid_tgid, parent_pid_tgid);
        let parent_cwd = self.cwd_map.get(&parent_pid_tgid).unwrap();
        self.cwd_map.insert(child_pid_tgid, parent_cwd.clone());
        let parent_pid = upid_of(parent_pid_tgid);
        let child_pid = upid_of(child_pid_tgid);
        let fd_table = self
            .fd_tables
            .get(&parent_pid)
            .expect(format!("missing fd table for {parent_pid}").as_str());
        let mut child_fd_table = fd_table.clone();
        for (_fd_, file_desc) in child_fd_table.iter_mut() {
            self.open_files.increment_ref_count(file_desc.open_file);
        }
        self.fd_tables.insert(child_pid, child_fd_table);
    }

    pub fn open_file(
        &mut self,
        pid_tgid: u64,
        new_fd: i32,
        fd_flags: u32,
        status_flags: u32,
        path: PathBuf,
    ) {
        let pid = upid_of(pid_tgid);
        let open_file = self.open_files.open_file(status_flags, path);
        let fd_table = self
            .fd_tables
            .get_mut(&pid)
            .expect(format!("expected fd table for pid {pid}").as_str());
        fd_table.insert(
            new_fd,
            FileDesc {
                fd_flags,
                open_file,
            },
        );
    }

    pub fn dup_file(&mut self, pid_tgid: u64, old_fd: i32, new_fd: i32, fd_flags: u32) {
        let pid = upid_of(pid_tgid);
        let fd_table = self
            .fd_tables
            .get_mut(&pid)
            .expect(format!("expected fd table for pid {pid}").as_str());
        let old_file_desc = fd_table
            .get(&old_fd)
            .expect(format!("expected old fd {old_fd} to be present for pid {pid}").as_str());
        let open_file = old_file_desc.open_file;
        self.open_files.increment_ref_count(open_file);
        fd_table.insert(
            new_fd,
            FileDesc {
                fd_flags,
                open_file,
            },
        );
    }

    pub fn create_pipe(&mut self, pid_tgid: u64, fd1: i32, fd2: i32, flags: u32, path: PathBuf) {
        let pid = upid_of(pid_tgid);
        let read_end = self.open_files.open_file(0, path.clone());
        let write_end = self.open_files.open_file(0, path);
        let fd_table = self
            .fd_tables
            .get_mut(&pid)
            .expect(format!("expected fd table for pid {pid}").as_str());
        let fd_flags = if flags & libc::O_CLOEXEC as u32 > 0 {
            libc::FD_CLOEXEC as u32
        } else {
            0
        };
        fd_table.insert(
            fd1,
            FileDesc {
                fd_flags,
                open_file: read_end,
            },
        );
        fd_table.insert(
            fd2,
            FileDesc {
                fd_flags,
                open_file: write_end,
            },
        );
    }

    pub fn close_file(&mut self, pid_tgid: u64, fd: i32) {
        let pid = upid_of(pid_tgid);
        let fd_table = self
            .fd_tables
            .get_mut(&pid)
            .expect(format!("expected fd table for pid {pid}").as_str());
        if !fd_table.contains_key(&fd) {
            println!("{fd}");
            println!("{fd_table:#?}")
        }
        self.open_files
            .close_file(fd_table.get(&fd).unwrap().open_file);
        fd_table.remove(&fd);
    }

    pub fn get_fd_flags(&mut self, pid_tgid: u64, fd: i32) -> u32 {
        let pid = upid_of(pid_tgid);
        let fd_table = self
            .fd_tables
            .get_mut(&pid)
            .expect(format!("expected fd table for pid {pid}").as_str());
        let file_desc = fd_table
            .get(&fd)
            .expect(format!("expected fd {fd} to be present for pid {pid}").as_str());
        file_desc.fd_flags
    }

    pub fn set_fd_flags(&mut self, pid_tgid: u64, fd: i32, fd_flags: u32) {
        let pid = upid_of(pid_tgid);
        let fd_table = self
            .fd_tables
            .get_mut(&pid)
            .expect(format!("expected fd table for pid {pid}").as_str());
        let file_desc = fd_table
            .get_mut(&fd)
            .expect(format!("expected fd {fd} to be present for pid {pid}").as_str());
        file_desc.fd_flags = fd_flags;
    }

    pub fn get_path_from_fd(&self, pid_tgid: u64, fd: i32) -> PathBuf {
        let pid = upid_of(pid_tgid);
        let fd_table = self
            .fd_tables
            .get(&pid)
            .expect(format!("expected fd table for pid {pid}").as_str());
        let file_desc = fd_table
            .get(&fd)
            .expect(format!("expected fd for pid {pid}").as_str());
        let open_file = self
            .open_files
            .get_path(file_desc.open_file)
            .expect(format!("expected open file {}", file_desc.open_file).as_str());
        open_file.path.clone()
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
    EventFcntl {
        pid_tgid: u64,
        ret: i64,
        syscall_nr: i64,
        fd: i32,
        cmd: u32,
        arg: u64,
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
            libc::SYS_clone => parse_clone(&mut ctxt, pid_tgid, ret),
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
            libc::SYS_dup => parse_dup(&mut ctxt, pid_tgid, ret, fd),
            libc::SYS_inotify_add_watch => {
                parse_sys_inotify_add_watch(&mut ctxt, &mut sets, pid_tgid, &path)
            }
            libc::SYS_openat | libc::SYS_openat2 => {
                parse_openat(&mut ctxt, &mut sets, pid_tgid, ret, flags, fd, &path)
            }
            // #[cfg(target_arch = "x86_64")]
            // libc::SYS_open => {
            //     let mut ctxt = CTXT.lock().unwrap();
            //     let mut sets = SETS.lock().unwrap();
            //     parse_open(
            //         &mut ctxt, &mut sets, pid_tgid, ret, syscall_nr, flags, fd, &path,
            //     )
            // }
            libc::SYS_chdir => parse_chdir(&mut ctxt, &mut sets, pid_tgid, ret, &path),
            libc::SYS_symlinkat => parse_symlinkat(
                &mut ctxt, &mut sets, pid_tgid, ret, syscall_nr, flags, fd, &path,
            ),
            // libc::SYS_symlink => {}
            // r path
            libc::SYS_execve | libc::SYS_statfs | libc::SYS_getxattr | libc::SYS_lgetxattr => {
                parse_r_first_path_e1(&mut ctxt, &mut sets, pid_tgid, &path)
            }
            // libc::SYS_stat => {}
            // libc::SYS_lstat => {}
            // libc::SYS_access => {}
            // libc::SYS_readlink => {}
            // w path
            libc::SYS_truncate | libc::SYS_acct => {
                parse_w_first_path_e1(&mut ctxt, &mut sets, pid_tgid, ret, &path)
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
            libc::SYS_newfstatat
            | libc::SYS_statx
            | libc::SYS_name_to_handle_at
            | libc::SYS_readlinkat
            | libc::SYS_faccessat
            | libc::SYS_faccessat2
            | libc::SYS_execveat => parse_r_fd_path_e1(&mut ctxt, &mut sets, pid_tgid, fd, &path),
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
            libc::SYS_memfd_create => {
                parse_memfd_create(&mut ctxt, &mut sets, pid_tgid, ret, flags, fd, &path)
            }

            // libc::SYS_close => parse_close(&mut ctxt, &mut sets, pid_tgid, ret, flags, fd, &path),
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
            libc::SYS_dup3 => parse_dup23(&mut ctxt, pid_tgid, ret, flags, fd, fd2),
            // libc::SYS_link => {}
            // libc::SYS_rename => {}
            libc::SYS_renameat | libc::SYS_renameat2 => parse_renameat(
                &mut ctxt, &mut sets, pid_tgid, ret, syscall_nr, flags, fd, &path, fd2, &path2,
            ),
            libc::SYS_pipe2 => parse_pipe2(&mut ctxt, &mut sets, pid_tgid, flags, fd, &path, fd2),
            _ => {}
        },
        SyscallInfo::EventFcntl {
            pid_tgid,
            ret,
            syscall_nr: _,
            fd,
            cmd,
            arg,
        } => parse_fcntl(&mut ctxt, pid_tgid, ret, fd, cmd, arg),
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
                ctxt.get_path_from_fd(pid_tgid, fd)
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

fn parse_memfd_create(
    ctxt: &mut Context,
    sets: &mut RWSet,
    pid_tgid: u64,
    ret: i64,
    flags: u32,
    fd: i32,
    path: &str,
) {
    if ret < 0 {
        return;
    }

    let new_fd = ret as i32;

    let fd_flags = if flags & libc::MFD_CLOEXEC as u32 != 0 {
        libc::FD_CLOEXEC as u32
    } else {
        0
    };

    // Shared open-file description flags: always O_RDWR for a fresh memfd
    let status_flags = libc::O_RDWR as u32;

    let path = PathBuf::from("/memfd::".to_owned() + path);
    insert_with_ancestors(sets, path.clone(), AccessKind::Read);
    insert_with_ancestors(sets, path.clone(), AccessKind::Write);

    ctxt.open_file(pid_tgid, new_fd, fd_flags, status_flags, path);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AccessKind {
    Read,
    Write,
}

fn parse_fcntl(ctxt: &mut Context, pid_tgid: u64, ret: i64, fd: i32, cmd: u32, arg: u64) {
    match cmd as i32 {
        libc::F_DUPFD => parse_dup(ctxt, pid_tgid, ret, fd),
        libc::F_DUPFD_CLOEXEC => ctxt.dup_file(pid_tgid, fd, ret as i32, libc::FD_CLOEXEC as u32),
        libc::F_GETFD => {
            ctxt.get_fd_flags(pid_tgid, fd);
        }
        libc::F_SETFD => ctxt.set_fd_flags(pid_tgid, fd, arg as u32),
        _ => {
            // other fcntl commands are not important to file dependencies
        }
    }
}

fn parse_dup(ctxt: &mut Context, pid_tgid: u64, ret: i64, fd: i32) {
    if ret < 0 {
        return;
    }

    let new_fd = match i32::try_from(ret) {
        Ok(x) => x,
        Err(_) => return,
    };

    ctxt.dup_file(pid_tgid, fd, new_fd, 0);
}

fn parse_dup23(ctxt: &mut Context, pid_tgid: u64, ret: i64, flags: u32, fd: i32, fd2: i32) {
    if ret as i32 == fd2 {
        ctxt.dup_file(pid_tgid, fd, fd2, flags);
    }
}

fn parse_pipe2(
    ctxt: &mut Context,
    sets: &mut RWSet,
    pid_tgid: u64,
    flags: u32,
    fd: i32,
    path: &str,
    fd2: i32,
) {
    let path = convert_absolute(ctxt, pid_tgid, path, None);
    ctxt.create_pipe(pid_tgid, fd, fd2, flags, path.clone());
    insert_with_ancestors(sets, path.clone(), AccessKind::Read);
    insert_with_ancestors(sets, path, AccessKind::Write);
}

fn parse_sys_inotify_add_watch(ctxt: &mut Context, sets: &mut RWSet, pid_tgid: u64, path: &str) {
    if path.is_empty() {
        return;
    }
    let abs = convert_absolute(ctxt, pid_tgid, path, None);

    insert_with_ancestors(sets, abs, AccessKind::Read);
}

fn parse_openat(
    ctxt: &mut Context,
    sets: &mut RWSet,
    pid_tgid: u64,
    ret: i64,
    flags: u32,
    fd: i32,
    path: &str,
) {
    let abs = convert_absolute(&ctxt, pid_tgid, &path, Some(fd));
    if ret >= 0 {
        let new_fd = ret as i32;
        let mut fd_flags = 0;
        if flags & libc::O_CLOEXEC as u32 != 0 {
            fd_flags |= libc::FD_CLOEXEC as u32;
        }
        let status_flags = flags & !(libc::O_CLOEXEC as u32);

        ctxt.open_file(pid_tgid, new_fd, fd_flags, status_flags, abs.clone());

        // TODO: Why this is needed?
        // if (flags & libc::O_DIRECTORY as u32) != 0 {
        //     ctxt.dirfd_map.insert((pid_tgid, new_fd), abs.clone());
        // }
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

fn parse_close(
    ctxt: &mut Context,
    sets: &mut RWSet,
    pid_tgid: u64,
    ret: i64,
    flags: u32,
    fd: i32,
    path: &str,
) {
    if ret >= 0 {
        ctxt.close_file(pid_tgid, fd);
    }
}

fn parse_open(
    ctxt: &mut Context,
    sets: &mut RWSet,
    pid_tgid: u64,
    ret: i64,
    flags: u32,
    path: &str,
) {
    let abs = convert_absolute(&ctxt, pid_tgid, &path, None);
    // TODO: Why is this needed?
    // if ret >= 0 && (flags & libc::O_DIRECTORY as u32) != 0 {
    //     ctxt.dirfd_map.insert((pid_tgid, ret as i32), abs.clone());
    // }

    if ret >= 0 {
        let new_fd = ret as i32;
        let mut fd_flags = 0;
        if flags & libc::O_CLOEXEC as u32 != 0 {
            fd_flags |= libc::FD_CLOEXEC as u32;
        }
        let status_flags = flags & !(libc::O_CLOEXEC as u32);

        ctxt.open_file(pid_tgid, new_fd, fd_flags, status_flags, abs.clone());
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

fn parse_chdir(ctxt: &mut Context, sets: &mut RWSet, pid_tgid: u64, ret: i64, path: &str) {
    let abs = convert_absolute(ctxt, pid_tgid, &path, None);
    if ret == 0 {
        ctxt.cwd_map.insert(pid_tgid, abs.clone());
    }
    insert_with_ancestors(sets, abs, AccessKind::Read);
}

fn parse_clone(ctxt: &mut Context, pid_tgid: u64, ret: i64) {
    if ret < 0 {
        return;
    };
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

fn parse_r_first_path_e1(ctxt: &mut Context, sets: &mut RWSet, pid_tgid: u64, path: &str) {
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

fn parse_r_fd_path_e1(ctxt: &mut Context, sets: &mut RWSet, pid_tgid: u64, fd: i32, path: &str) {
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
            Ok(Some(SyscallEvent::Enter1(e))) => {
                let pid_tgid = e.pid_tgid as u64;
                let mut logs = LOGS.lock().unwrap();
                logs.update_log(pid_tgid, SyscallEvent::Enter1(e))
            }
            Ok(Some(SyscallEvent::Enter2(e))) => {
                let pid_tgid = e.pid_tgid as u64;
                let mut logs = LOGS.lock().unwrap();
                logs.update_log(pid_tgid, SyscallEvent::Enter2(e))
            }
            Ok(Some(SyscallEvent::EnterFcntl(e))) => {
                let pid_tgid = e.pid_tgid as u64;
                let mut logs = LOGS.lock().unwrap();
                logs.update_log(pid_tgid, SyscallEvent::EnterFcntl(e))
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
                        SyscallEvent::EnterFcntl(e) => {
                            on_event_update_rw_sets(SyscallInfo::EventFcntl {
                                pid_tgid: e.pid_tgid as u64,
                                ret: exit_info.ret,
                                syscall_nr: e.syscall_nr,
                                fd: e.fd,
                                cmd: e.cmd,
                                arg: e.arg,
                            })
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
