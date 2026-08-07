use crate::cli::Output;
use anyhow::Result;
use libc::{self};
use once_cell::sync::Lazy;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::io::Write;
use std::path::{Component, PathBuf};
use std::sync::mpsc;
use std::sync::Mutex;
use syscallnrs::syscall_of_nr;
use fstrace::*;
pub struct StreamCfg {
    pub read_out: Option<Output>,
    pub write_out: Option<Output>,
    pub trace_out: Option<Output>,
}
#[inline(always)]
pub fn upid_of(pid_tgid: u64) -> u32 {
    // NOTE: userspace pid = kernel tgid
    (pid_tgid & 0xFFFFFFFF) as u32
}

#[inline(always)]
pub fn utid_of(pid_tgid: u64) -> u32 {
    (pid_tgid >> 32) as u32
}

#[derive(Debug)]
pub enum SyscallEvent {
    Enter {
        pid_tgid: u64,
        syscall_nr: i64,
        event_type: u32,
        flags: u32,
        cmd: u64,
        arg: u64,
        fd: i32,
        fd2: i32,
        path1: String,
        path2: String,
    },
    Exit {
        pid_tgid: u64,
        ret: i64,
    },
}
impl fmt::Display for SyscallEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyscallEvent::Enter {
                pid_tgid: _,
                syscall_nr,
                event_type: _,
                flags,
                cmd,
                arg,
                fd,
                fd2,
                path1,
                path2,
            } => {
                let syscall = match syscall_of_nr(*syscall_nr as u64) {
                    Some(syscall) => syscall,
                    None => "syscall_nr not found",
                };
                if syscall == "fcntl" {
                    write!(f, "{}(fd={},cmd={},arg={})", syscall, fd, cmd, arg)
                } else {
                    write!(
                        f,
                        "{}(fd={},path={},fd2={},path2={},flags={})",
                        syscall, fd, path1, fd2, path2, flags
                    )
                }
            }
            SyscallEvent::Exit { pid_tgid: _, ret } => {
                writeln!(f, " -> {}", ret)
            }
        }
    }
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
        for (pid_tgid, vec) in &self.log {
            println!("{pid_tgid}");
            let a = vec.len();
            println!("{a}");
        }
    }
    pub fn update_log(&mut self, pid_tgid: u64, event: SyscallEvent) {
        self.log
            .entry(pid_tgid)
            .or_insert_with(|| VecDeque::new())
            .push_back(event);
    }

    pub fn dump_log(&mut self, mut out: impl std::io::Write) -> Result<()> {
        let mut sorted_logs: Vec<_> = self
            .log
            .iter()
            .map(|(pid_tgid, logs)| (upid_of(*pid_tgid), utid_of(*pid_tgid), logs))
            .collect();

        sorted_logs.sort_by(|(pid1, _, _), (pid2, _, _)| pid1.cmp(pid2));

        for (pid, tid, log) in sorted_logs {
            writeln!(out, "log for pid {} tid {}:", pid, tid)?;
            for e in log.iter() {
                write!(out, "{e}")?;
            }
        }

        Ok(())
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

    #[allow(dead_code)]
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

    #[allow(dead_code)]
    pub fn get_flags(&mut self, file: u32) -> u32 {
        let open_file = self
            .table
            .get(&file)
            .expect(format!("expected open file {file} to retrieve status flags").as_str());

        open_file.status_flags
    }

    #[allow(dead_code)]
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
        // println!("clone: parent {fd_table:#?}");
        let mut child_fd_table = fd_table.clone();
        // println!("clone: child {child_fd_table:#?}");
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
        // println!("ctxt.dup_file: {fd_table:#?}");
        // An fd with no entry was opened before this tracer started recording:
        // either before the exec marker lifted suppression, or before attaching
        // to an already-running process. Such an fd cannot be a dependency of
        // the traced program — the program's own opens are all recorded — so
        // leave the duplicate untracked rather than killing the tracer, which
        // would discard the whole run. (Events genuinely lost to a full ring
        // buffer are a different case, and are already accounted for separately
        // by the missed-event counter.)
        let Some(old_file_desc) = fd_table.get(&old_fd) else {
            return;
        };
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
        // println!("fds passed to create_pipe are {fd1} and {fd2}");
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
        // println!("{fd_table:#?}");
    }

    #[allow(dead_code)]
    pub fn close_file(&mut self, pid_tgid: u64, fd: i32) {
        let pid = upid_of(pid_tgid);
        let fd_table = self
            .fd_tables
            .get_mut(&pid)
            .expect(format!("expected fd table for pid {pid}").as_str());
        // if !fd_table.contains_key(&fd) {
        //     println!("{fd}");
        //     println!("{fd_table:#?}")
        // }
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
        // Unknown fd: predates recording (see dup_file). Report no flags set.
        let Some(file_desc) = fd_table.get(&fd) else {
            return 0;
        };
        file_desc.fd_flags
    }

    pub fn set_fd_flags(&mut self, pid_tgid: u64, fd: i32, fd_flags: u32) {
        let pid = upid_of(pid_tgid);
        let fd_table = self
            .fd_tables
            .get_mut(&pid)
            .expect(format!("expected fd table for pid {pid}").as_str());
        // Unknown fd: predates recording (see dup_file). Nothing to update.
        let Some(file_desc) = fd_table.get_mut(&fd) else {
            return;
        };
        file_desc.fd_flags = fd_flags;
    }

    pub fn get_path_from_fd(&self, pid_tgid: u64, fd: i32) -> PathBuf {
        let pid = upid_of(pid_tgid);
        let fd_table = self
            .fd_tables
            .get(&pid)
            .expect(format!("expected fd table for pid {pid}").as_str());
        // Unknown fd: predates recording (see dup_file), so its path was never
        // seen. Resolve to the fd's own procfs name — accurate, and anything
        // built on it stays under /proc, which dependency consumers ignore, so
        // an unresolvable directory fd cannot invent a bogus dependency.
        let Some(file_desc) = fd_table.get(&fd) else {
            return PathBuf::from(format!("/proc/{pid}/fd/{fd}"));
        };
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

    pub fn update_read_set(&mut self, path: PathBuf) -> bool {
        self.read_set.insert(path)
    }
    pub fn update_write_set(&mut self, path: PathBuf) -> bool {
        self.write_set.insert(path)
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

    pub fn dump_sets(&mut self, mut out: impl std::io::Write) -> Result<()> {
        let rset = &self.read_set;
        let wset = &self.write_set;

        writeln!(out, "Read set")?;

        let mut r = Vec::from_iter(rset);
        r.sort();

        for p in r {
            writeln!(out, "{p:?}")?;
        }

        writeln!(out, "Write set")?;

        let mut w = Vec::from_iter(wset);
        w.sort();

        for p in w {
            writeln!(out, "{p:?}")?;
        }
        Ok(())
    }
}

pub static CTXT: Lazy<Mutex<Context>> = Lazy::new(|| Mutex::new(Context::new()));
pub static SETS: Lazy<Mutex<RWSet>> = Lazy::new(|| Mutex::new(RWSet::new()));
pub static LOGS: Lazy<Mutex<Logs>> = Lazy::new(|| Mutex::new(Logs::new()));

enum SyscallInfo<'a> {
    Event0 {
        pid_tgid: u64,
        ret: i64,
        syscall_nr: i64,
        #[allow(dead_code)]
        flags: u32,
    },
    Event1 {
        pid_tgid: u64,
        ret: i64,
        syscall_nr: i64,
        flags: u32,
        fd: i32,
        path: &'a str,
    },
    Event2 {
        pid_tgid: u64,
        ret: i64,
        syscall_nr: i64,
        flags: u32,
        fd: i32,
        path: &'a str,
        fd2: i32,
        path2: &'a str,
    },
    EventFcntl {
        pid_tgid: u64,
        ret: i64,
        fd: i32,
        cmd: u64,
        arg: u64,
    },
}

fn on_event_update_rw_sets(event: SyscallInfo, s_cfg: &mut Option<StreamCfg>) {
    let mut ctxt = CTXT.lock().unwrap();
    let mut sets = SETS.lock().unwrap();
    match event {
        SyscallInfo::Event0 {
            pid_tgid,
            ret,
            syscall_nr,
            flags: _,
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
                parse_sys_inotify_add_watch(&mut ctxt, &mut sets, pid_tgid, path, s_cfg)
            }
            libc::SYS_openat | libc::SYS_openat2 => {
                parse_openat(&mut ctxt, &mut sets, pid_tgid, ret, flags, fd, path, s_cfg)
            }
            #[cfg(target_arch = "x86_64")]
            libc::SYS_open => parse_open(&mut ctxt, &mut sets, pid_tgid, ret, flags, &path, s_cfg),
            libc::SYS_chdir => parse_chdir(&mut ctxt, &mut sets, pid_tgid, ret, path, s_cfg),
            libc::SYS_symlinkat => {
                parse_symlinkat(&mut ctxt, &mut sets, pid_tgid, ret, fd, path, s_cfg)
            }
            // libc::SYS_symlink => {}
            // r path
            libc::SYS_execve | libc::SYS_statfs | libc::SYS_getxattr | libc::SYS_lgetxattr => {
                parse_r_first_path_e1(&mut ctxt, &mut sets, pid_tgid, path, s_cfg)
            }
            // libc::SYS_stat => {}
            // libc::SYS_lstat => {}
            // libc::SYS_access => {}
            // libc::SYS_readlink => {}
            // w path
            libc::SYS_truncate | libc::SYS_acct => {
                parse_w_first_path_e1(&mut ctxt, &mut sets, pid_tgid, ret, path, s_cfg)
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
            | libc::SYS_execveat => {
                parse_r_fd_path_e1(&mut ctxt, &mut sets, pid_tgid, fd, path, s_cfg)
            }
            // w fd path
            libc::SYS_linkat
            | libc::SYS_unlinkat
            | libc::SYS_utimensat
            | libc::SYS_mkdirat
            | libc::SYS_mknodat
            | libc::SYS_fchownat
            | libc::SYS_fchmodat => {
                parse_w_fd_path_e1(&mut ctxt, &mut sets, pid_tgid, ret, fd, path, s_cfg)
            }
            // libc::SYS_futimeat => {}
            libc::SYS_memfd_create => {
                parse_memfd_create(&mut ctxt, &mut sets, pid_tgid, ret, flags, fd, path, s_cfg)
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
            // dup2 only exists on architectures with the legacy syscall table
            // (on arm64, glibc routes dup2() through dup3). Missing this arm
            // means the duplicated fd never enters the fd table, and a later
            // successful fcntl on it (e.g. bash's F_SETFD after moving its
            // script fd to 255) panics in set_fd_flags. Unlike dup3, dup2
            // carries no flags and old_fd == new_fd is a successful no-op.
            #[cfg(target_arch = "x86_64")]
            libc::SYS_dup2 => {
                if fd != fd2 {
                    parse_dup23(&mut ctxt, pid_tgid, ret, 0, fd, fd2)
                }
            }
            // libc::SYS_link => {}
            // libc::SYS_rename => {}
            libc::SYS_renameat | libc::SYS_renameat2 => {
                parse_renameat(&mut ctxt, &mut sets, pid_tgid, fd, path, fd2, path2, s_cfg)
            }
            libc::SYS_pipe2 => {
                parse_pipe2(&mut ctxt, &mut sets, pid_tgid, flags, fd, path, fd2, s_cfg)
            }
            _ => {}
        },
        SyscallInfo::EventFcntl {
            pid_tgid,
            ret,
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
                // let a = &ctxt.cwd_map;
                // let c = upid_of(pid_tgid);
                // let d = utid_of(pid_tgid);
                // println!("{a:#?}, {pid_tgid}, {c}, {d}");
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
    _fd: i32,
    path: &str,
    s_cfg: &mut Option<StreamCfg>,
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
    insert_with_ancestors(sets, path.clone(), AccessKind::Read, s_cfg);
    insert_with_ancestors(sets, path.clone(), AccessKind::Write, s_cfg);

    ctxt.open_file(pid_tgid, new_fd, fd_flags, status_flags, path);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AccessKind {
    Read,
    Write,
}

fn parse_fcntl(ctxt: &mut Context, pid_tgid: u64, ret: i64, fd: i32, cmd: u64, arg: u64) {
    // A failed fcntl can't change fd state, and may reference an fd that was
    // never opened (e.g. bash probes fcntl(255, F_GETFD) -> EBADF at script
    // startup before dup'ing the script fd there).
    if ret < 0 {
        return;
    }
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
    s_cfg: &mut Option<StreamCfg>,
) {
    let path = convert_absolute(ctxt, pid_tgid, path, None);
    ctxt.create_pipe(pid_tgid, fd, fd2, flags, path.clone());
    insert_with_ancestors(sets, path.clone(), AccessKind::Read, s_cfg);
    insert_with_ancestors(sets, path, AccessKind::Write, s_cfg);
}

fn parse_sys_inotify_add_watch(
    ctxt: &mut Context,
    sets: &mut RWSet,
    pid_tgid: u64,
    path: &str,
    s_cfg: &mut Option<StreamCfg>,
) {
    if path.is_empty() {
        return;
    }
    let abs = convert_absolute(ctxt, pid_tgid, path, None);

    insert_with_ancestors(sets, abs, AccessKind::Read, s_cfg);
}

fn parse_openat(
    ctxt: &mut Context,
    sets: &mut RWSet,
    pid_tgid: u64,
    ret: i64,
    flags: u32,
    fd: i32,
    path: &str,
    s_cfg: &mut Option<StreamCfg>,
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
        insert_with_ancestors(sets, abs, AccessKind::Read, s_cfg);
    } else {
        // Check the access mode (lower 2 bits of flags)
        let access_mode = (flags & libc::O_ACCMODE as u32) as i32;

        match access_mode {
            libc::O_RDONLY => {
                insert_with_ancestors(sets, abs, AccessKind::Read, s_cfg);
            }
            libc::O_WRONLY => {
                insert_with_ancestors(sets, abs, AccessKind::Write, s_cfg);
            }
            libc::O_RDWR => {
                // File is opened for both reading and writing
                insert_with_ancestors(sets, abs.clone(), AccessKind::Read, s_cfg);
                insert_with_ancestors(sets, abs, AccessKind::Write, s_cfg);
            }
            _ => {
                // Shouldn't happen, but default to read
                insert_with_ancestors(sets, abs, AccessKind::Read, s_cfg);
            }
        }
    }
}

#[allow(dead_code)]
fn parse_close(ret: i64) {
    if ret >= 0 {
        // ctxt.close_file(pid_tgid, fd);
    }
}

#[cfg(target_arch = "x86_64")]
fn parse_open(
    ctxt: &mut Context,
    sets: &mut RWSet,
    pid_tgid: u64,
    ret: i64,
    flags: u32,
    path: &str,
    s_cfg: &mut Option<StreamCfg>,
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
    insert_with_ancestors(sets, abs, kind, s_cfg);
}

fn parse_chdir(
    ctxt: &mut Context,
    sets: &mut RWSet,
    pid_tgid: u64,
    ret: i64,
    path: &str,
    s_cfg: &mut Option<StreamCfg>,
) {
    let abs = convert_absolute(ctxt, pid_tgid, &path, None);
    if ret == 0 {
        ctxt.cwd_map.insert(pid_tgid, abs.clone());
    }
    insert_with_ancestors(sets, abs, AccessKind::Read, s_cfg);
}

fn parse_clone(ctxt: &mut Context, pid_tgid: u64, ret: i64) {
    if ret < 0 {
        return;
    };
    //println!("HEREERER");
    //println!("{pid_tgid}, {ret}");
    ctxt.do_clone(pid_tgid, ret as u64)
}

fn parse_symlinkat(
    ctxt: &mut Context,
    sets: &mut RWSet,
    pid_tgid: u64,
    ret: i64,
    fd: i32,
    path: &str,
    s_cfg: &mut Option<StreamCfg>,
) {
    let abs = convert_absolute(ctxt, pid_tgid, &path, Some(fd));
    let kind = if ret != 0 {
        AccessKind::Read
    } else {
        AccessKind::Write
    };

    insert_with_ancestors(sets, abs, kind, s_cfg);
}

fn parse_r_first_path_e1(
    ctxt: &mut Context,
    sets: &mut RWSet,
    pid_tgid: u64,
    path: &str,
    s_cfg: &mut Option<StreamCfg>,
) {
    if path.is_empty() {
        return;
    }
    let abs = convert_absolute(ctxt, pid_tgid, &path, None);

    insert_with_ancestors(sets, abs, AccessKind::Read, s_cfg);
}

fn parse_w_first_path_e1(
    ctxt: &mut Context,
    sets: &mut RWSet,
    pid_tgid: u64,
    ret: i64,
    path: &str,
    s_cfg: &mut Option<StreamCfg>,
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

    insert_with_ancestors(sets, abs, kind, s_cfg);
}

fn parse_r_fd_path_e1(
    ctxt: &mut Context,
    sets: &mut RWSet,
    pid_tgid: u64,
    fd: i32,
    path: &str,
    s_cfg: &mut Option<StreamCfg>,
) {
    if path.is_empty() {
        return;
    }

    let abs = convert_absolute(ctxt, pid_tgid, path, Some(fd));

    insert_with_ancestors(sets, abs, AccessKind::Read, s_cfg);
}

fn parse_w_fd_path_e1(
    ctxt: &mut Context,
    sets: &mut RWSet,
    pid_tgid: u64,
    ret: i64,
    fd: i32,
    path: &str,
    s_cfg: &mut Option<StreamCfg>,
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

    insert_with_ancestors(sets, abs, kind, s_cfg);
}

fn parse_renameat(
    ctxt: &mut Context,
    sets: &mut RWSet,
    pid_tgid: u64,
    fd: i32,
    path: &str,
    fd2: i32,
    path2: &str,
    s_cfg: &mut Option<StreamCfg>,
) {
    let abs_path_1 = convert_absolute(ctxt, pid_tgid, path, Some(fd));
    let abs_path_2 = convert_absolute(ctxt, pid_tgid, path2, Some(fd2));

    insert_with_ancestors(sets, abs_path_1, AccessKind::Write, s_cfg);
    insert_with_ancestors(sets, abs_path_2, AccessKind::Write, s_cfg);
}

fn emit_rw(s_cfg: &mut Option<StreamCfg>, kind: AccessKind, p: &PathBuf) {
    let Some(cfg) = s_cfg.as_mut() else { return };

    // Flush after every line: the scheduler tails these files live to detect
    // conflicts while the command runs. Without the flush the BufWriter only
    // hands data to the file at exit, so streaming never actually streams.
    match kind {
        AccessKind::Read => {
            if let Some(out) = cfg.read_out.as_mut() {
                let _ = writeln!(out, "{}", p.display());
                let _ = out.flush();
            }
        }
        AccessKind::Write => {
            if let Some(out) = cfg.write_out.as_mut() {
                let _ = writeln!(out, "{}", p.display());
                let _ = out.flush();
            }
        }
    }
}

fn insert_with_ancestors(
    sets: &mut RWSet,
    p: PathBuf,
    kind: AccessKind,
    s_cfg: &mut Option<StreamCfg>,
) {
    let mut check: bool;
    match kind {
        AccessKind::Read => {
            check = sets.update_read_set(p.clone());
            if check {
                emit_rw(s_cfg, AccessKind::Read, &p);
            }
            for dir in RWSet::compute_closure(p) {
                check = sets.update_read_set(dir.clone());
                if check {
                    emit_rw(s_cfg, AccessKind::Read, &dir);
                }
            }
        }
        AccessKind::Write => {
            check = sets.update_write_set(p.clone());
            if check {
                emit_rw(s_cfg, AccessKind::Write, &p);
            }
            for dir in RWSet::compute_closure(p) {
                check = sets.update_read_set(dir.clone());
                if check {
                    emit_rw(s_cfg, AccessKind::Read, &dir);
                }
            }
        }
    }
}

pub fn event_stream_handler(
    rx: mpsc::Receiver<Option<SyscallEvent>>,
    mut s_cfg: Option<StreamCfg>,
) -> Result<()> {
    loop {
        match rx.recv() {
            Ok(Some(enter @ SyscallEvent::Enter { pid_tgid, .. })) => {
                // print!("{enter}");
                let mut logs = LOGS.lock().unwrap();
                if let Some(cfg) = s_cfg.as_mut() {
                    if let Some(out) = cfg.trace_out.as_mut() {
                        write!(out, "{enter}")?;
                    }
                }
                logs.update_log(pid_tgid, enter);
            }
            Ok(Some(exit @ SyscallEvent::Exit { pid_tgid, ret })) => {
                // print!("{exit}");
                if let Some(cfg) = s_cfg.as_mut() {
                    if let Some(out) = cfg.trace_out.as_mut() {
                        write!(out, "{exit}")?;
                    }
                }
                let mut logs = LOGS.lock().unwrap();
                logs.update_log(pid_tgid, exit);
                let event_queue = logs.log.get(&pid_tgid).unwrap();
                let len = event_queue.len();
                if len >= 2 {
                    if let SyscallEvent::Enter {
                        pid_tgid,
                        syscall_nr,
                        event_type,
                        flags,
                        cmd,
                        arg,
                        fd,
                        fd2,
                        path1,
                        path2,
                    } = &event_queue[len - 2]
                    {
                        if *event_type == sys_enter_event_type_t_ENTER_PATH0 {
                            on_event_update_rw_sets(
                                SyscallInfo::Event0 {
                                    pid_tgid: *pid_tgid,
                                    ret,
                                    syscall_nr: *syscall_nr,
                                    flags: *flags,
                                },
                                &mut s_cfg,
                            );
                        }
                        if *event_type == sys_enter_event_type_t_ENTER_PATH1 {
                            on_event_update_rw_sets(
                                SyscallInfo::Event1 {
                                    pid_tgid: *pid_tgid,
                                    ret,
                                    syscall_nr: *syscall_nr,
                                    flags: *flags,
                                    fd: *fd,
                                    path: &*path1,
                                },
                                &mut s_cfg,
                            );
                        }
                        if *event_type == sys_enter_event_type_t_ENTER_PATH2 {
                            on_event_update_rw_sets(
                                SyscallInfo::Event2 {
                                    pid_tgid: *pid_tgid,
                                    ret,
                                    syscall_nr: *syscall_nr,
                                    flags: *flags,
                                    fd: *fd,
                                    path: &*path1,
                                    fd2: *fd2,
                                    path2: &*path2,
                                },
                                &mut s_cfg,
                            );
                        }
                        if *event_type == sys_enter_event_type_t_ENTER_FCNTL {
                            on_event_update_rw_sets(
                                SyscallInfo::EventFcntl {
                                    pid_tgid: *pid_tgid,
                                    ret,
                                    fd: *fd,
                                    cmd: *cmd,
                                    arg: *arg,
                                },
                                &mut s_cfg,
                            );
                        }
                    }

                    // SyscallEvent::Enter1(e) => {
                    //     let path_cstr = unsafe { CStr::from_ptr(e.path.as_ptr()) };
                    //
                    //     on_event_update_rw_sets(SyscallInfo::Event1 {
                    //         pid_tgid: e.pid_tgid as u64,
                    //         ret: exit_info.ret,
                    //         syscall_nr: e.syscall_nr,
                    //         flags: e.flags as u32,
                    //         fd: e.fd,
                    //         path: String::from_utf8_lossy(path_cstr.to_bytes()).to_string(),
                    //     });
                    // }
                }
            }
            Ok(None) => break,
            Err(_) => {}
        }
    }
    Ok(())
}
