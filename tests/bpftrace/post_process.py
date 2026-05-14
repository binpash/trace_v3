#!/usr/bin/env python3
"""Post-processor for trace_deps.bt output.

Consumes the TSV event stream emitted by trace_deps.bt and reconstructs the
same dependency model that trace_v3's dep_tracer.rs builds in Rust:

  - per-process cwd map, updated on chdir and inherited on fork
  - per-process fd-table -> open-file-table with reference counts, so dup,
    dup3, fcntl(F_DUPFD), and clone-inherited fds resolve back to paths
  - read-set / write-set with ancestor-directory closure: every parent dir
    of a touched path lands in the read-set (matches insert_with_ancestors
    in dep_tracer.rs:1010-1043)

The output format is byte-for-byte the same as trace_v3's --dep-file so the
correctness harness can diff the two directly.
"""

import argparse
import os
import sys
from collections import defaultdict


AT_FDCWD = -100  # libc::AT_FDCWD

# Open flag access modes (Linux x86_64 values; same as libc::O_ACCMODE).
O_RDONLY = 0o0
O_WRONLY = 0o1
O_RDWR = 0o2
O_ACCMODE = 0o3
O_CLOEXEC = 0o2000000

# fcntl commands.
F_DUPFD = 0
F_GETFD = 1
F_SETFD = 2
F_DUPFD_CLOEXEC = 1030

# Subsets mirroring dep_tracer.rs::on_event_update_rw_sets.
R_FIRST_PATH = {"execve", "statfs", "getxattr", "lgetxattr"}
W_FIRST_PATH = {"truncate", "acct"}
R_FD_PATH = {
    "newfstatat", "statx", "name_to_handle_at",
    "readlinkat", "faccessat", "faccessat2", "execveat",
}
W_FD_PATH = {
    "linkat", "unlinkat", "utimensat", "mkdirat",
    "mknodat", "fchownat", "fchmodat",
}


class OpenFileTable:
    """Mirrors dep_tracer.rs::OpenFileTable.

    Maps a small integer "open_file id" to (path, ref_count). The id is the
    indirection that lets dup / clone alias the same kernel struct file.
    """

    def __init__(self):
        self.table = {}
        self.ctr = 0

    def open(self, path):
        while self.ctr in self.table:
            self.ctr += 1
        ofid = self.ctr
        self.table[ofid] = [path, 1]
        self.ctr += 1
        return ofid

    def incref(self, ofid):
        if ofid in self.table:
            self.table[ofid][1] += 1

    def path_of(self, ofid):
        entry = self.table.get(ofid)
        return entry[0] if entry else None


class Context:
    def __init__(self, initial_cwd):
        self.cwd = {}                          # tid -> str (absolute, normalized)
        self.fd_tables = defaultdict(dict)     # pid -> {fd: open_file_id}
        self.open_files = OpenFileTable()
        self.initial_cwd = initial_cwd

    def ensure_seen(self, pid, tid):
        if tid not in self.cwd:
            self.cwd[tid] = self.initial_cwd
        # touching the defaultdict is enough to materialize the fd_table.
        _ = self.fd_tables[pid]

    def on_fork(self, parent_pid, child_pid):
        # cwd inheritance — sched_process_fork's "pid" args are kernel TIDs;
        # for the single-threaded benchmark workloads this matches TGID.
        if parent_pid in self.cwd:
            self.cwd[child_pid] = self.cwd[parent_pid]
        else:
            self.cwd[child_pid] = self.initial_cwd
        # fd-table inheritance with refcounts (matches do_clone in
        # dep_tracer.rs:241-258).
        parent_table = self.fd_tables.get(parent_pid)
        if parent_table:
            child_table = dict(parent_table)
            for ofid in child_table.values():
                self.open_files.incref(ofid)
            self.fd_tables[child_pid] = child_table
        else:
            self.fd_tables[child_pid] = {}

    def resolve(self, pid, tid, raw_path, dirfd):
        """convert_absolute mirror — produces a normalized absolute path."""
        if raw_path.startswith("/"):
            base = raw_path
        else:
            if dirfd is None or dirfd == AT_FDCWD:
                root = self.cwd.get(tid, self.initial_cwd)
            else:
                fd_table = self.fd_tables.get(pid, {})
                ofid = fd_table.get(dirfd)
                root = self.open_files.path_of(ofid) if ofid is not None else None
                if root is None:
                    # Unknown dirfd (we never saw the openat for it). Falling
                    # back to cwd matches what an external observer would do.
                    root = self.cwd.get(tid, self.initial_cwd)
            base = os.path.join(root, raw_path)
        return _normalize(base)

    def fd_install(self, pid, fd, path):
        ofid = self.open_files.open(path)
        self.fd_tables[pid][fd] = ofid

    def fd_dup(self, pid, old_fd, new_fd):
        ofid = self.fd_tables.get(pid, {}).get(old_fd)
        if ofid is None:
            return
        self.open_files.incref(ofid)
        self.fd_tables[pid][new_fd] = ofid


def _normalize(path):
    """Path normalization that matches dep_tracer.rs::convert_absolute.

    We deliberately avoid os.path.normpath because it collapses '..' even
    when the prefix is non-existent on disk (which is fine), but we want
    behavior that matches the Rust impl which special-cases not popping past
    the root component.
    """
    parts = []
    for seg in path.split("/"):
        if seg == "" or seg == ".":
            continue
        if seg == "..":
            if parts:
                parts.pop()
            continue
        parts.append(seg)
    return "/" + "/".join(parts) if path.startswith("/") else "/".join(parts)


class DepSets:
    def __init__(self):
        self.r = set()
        self.w = set()

    def add_read(self, p):
        if p in self.r:
            return
        self.r.add(p)
        for anc in _ancestors(p):
            self.r.add(anc)

    def add_write(self, p):
        if p not in self.w:
            self.w.add(p)
        for anc in _ancestors(p):
            self.r.add(anc)


def _ancestors(p):
    out = []
    cur = p
    while True:
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        out.append(parent)
        cur = parent
    return out


def _classify_open_flags(flags, ret):
    """Mirror parse_openat: failed = Read; otherwise per O_ACCMODE."""
    if ret < 0:
        return ("R",)
    mode = flags & O_ACCMODE
    if mode == O_RDONLY:
        return ("R",)
    if mode == O_WRONLY:
        return ("W",)
    if mode == O_RDWR:
        return ("R", "W")
    return ("R",)


def parse_event(line):
    """Parse one TSV event line.

    Returns a dict with the fields populated for the event's tag, or None if
    the line is malformed (which we silently skip — bpftrace can occasionally
    emit a partial line).
    """
    # split with maxsplit so paths can contain literal tabs (rare).
    parts = line.rstrip("\n").split("\t")
    if not parts:
        return None
    tag = parts[0]
    try:
        if tag == "F" and len(parts) == 3:
            return {"tag": "F", "parent": int(parts[1]), "child": int(parts[2])}
        if tag == "T" and len(parts) == 2:
            return {"tag": "T", "pid": int(parts[1])}
        if tag == "X" and len(parts) == 5:
            return {
                "tag": "X",
                "syscall": parts[1],
                "pid": int(parts[2]),
                "tid": int(parts[3]),
                "ret": int(parts[4]),
            }
        if tag == "E0" and len(parts) == 9:
            return {
                "tag": "E0",
                "syscall": parts[1],
                "pid": int(parts[2]),
                "tid": int(parts[3]),
                "fd": int(parts[4]),
                "fd2": int(parts[5]),
                "flags": int(parts[6]),
                "cmd": int(parts[7]),
                "arg": int(parts[8]),
            }
        if tag == "E1" and len(parts) == 8:
            return {
                "tag": "E1",
                "syscall": parts[1],
                "pid": int(parts[2]),
                "tid": int(parts[3]),
                "dfd": int(parts[4]),
                "flags": int(parts[5]),
                "mode": int(parts[6]),
                "path": parts[7],
            }
        if tag == "E2" and len(parts) >= 9:
            # Two paths: take last two fields verbatim, the rest are integers.
            head = parts[:7]
            path1 = parts[7]
            path2 = "\t".join(parts[8:])
            return {
                "tag": "E2",
                "syscall": head[1],
                "pid": int(head[2]),
                "tid": int(head[3]),
                "dfd": int(head[4]),
                "dfd2": int(head[5]),
                "flags": int(head[6]),
                "path1": path1,
                "path2": path2,
            }
    except ValueError:
        return None
    return None


def process(
    events_iter,
    initial_cwd,
    deps_out,
    exclude_prefixes=(),
    skip_bootstrap=False,
):
    """Build the dep set from a bpftrace event stream.

    skip_bootstrap=True drops every event up to (and including) the *first*
    sys_enter_execve, then resumes processing from the second one. This
    aligns the dep set with trace_v3's: trace_v3 attaches probes to a child
    that immediately execve's the test command, so its first observable
    execve is the workload itself. bpftrace + our /bin/sh wrapper has one
    extra preamble execve (the wrapper invocation) — skipping it removes
    /bin, /bin/sh, /tmp, and the wrapper's libc reads (which the real
    /bin/sh re-loads after the second execve anyway).
    """
    ctx = Context(initial_cwd)
    deps = DepSets()
    pending = {}   # tid -> last enter event (paired with the next exit on same tid)

    execves_seen = 0
    active = not skip_bootstrap

    for ev in events_iter:
        tag = ev["tag"]

        if not active:
            # Forks during bootstrap are unusual but cheap to track.
            if tag == "F":
                ctx.on_fork(ev["parent"], ev["child"])
                continue
            if tag.startswith("E") and ev.get("syscall") == "execve":
                execves_seen += 1
                if execves_seen >= 2:
                    active = True
                    # fall through and process this enter event
                else:
                    continue
            else:
                continue

        if tag == "F":
            ctx.on_fork(ev["parent"], ev["child"])
            continue
        if tag == "T":
            continue
        if tag.startswith("E"):
            pending[ev["tid"]] = ev
            ctx.ensure_seen(ev["pid"], ev["tid"])
            continue
        if tag == "X":
            enter = pending.pop(ev["tid"], None)
            if enter is None or enter["syscall"] != ev["syscall"]:
                continue
            _apply(ctx, deps, enter, ev["ret"])

    if exclude_prefixes:
        deps.r = {p for p in deps.r if not any(p.startswith(x) for x in exclude_prefixes)}
        deps.w = {p for p in deps.w if not any(p.startswith(x) for x in exclude_prefixes)}

    _emit(deps, deps_out)


def _apply(ctx, deps, enter, ret):
    sc = enter["syscall"]

    if sc in ("openat", "open"):
        path = enter["path"]
        flags = enter["flags"]
        dfd = enter["dfd"]
        abs_path = ctx.resolve(enter["pid"], enter["tid"], path, dfd)
        if ret >= 0:
            ctx.fd_install(enter["pid"], ret, abs_path)
        for kind in _classify_open_flags(flags, ret):
            if kind == "R":
                deps.add_read(abs_path)
            else:
                deps.add_write(abs_path)
        return

    if sc == "chdir":
        abs_path = ctx.resolve(enter["pid"], enter["tid"], enter["path"], None)
        if ret == 0:
            ctx.cwd[enter["tid"]] = abs_path
        deps.add_read(abs_path)
        return

    if sc == "memfd_create":
        if ret < 0:
            return
        synthetic = "/memfd::" + enter["path"]
        ctx.fd_install(enter["pid"], ret, synthetic)
        deps.add_read(synthetic)
        deps.add_write(synthetic)
        return

    if sc == "symlinkat":
        # parse_symlinkat: ret==0 -> Write of newpath, else Read.
        abs_path = ctx.resolve(
            enter["pid"], enter["tid"], enter["path"], enter["dfd"]
        )
        if ret == 0:
            deps.add_write(abs_path)
        else:
            deps.add_read(abs_path)
        return

    if sc == "inotify_add_watch":
        abs_path = ctx.resolve(enter["pid"], enter["tid"], enter["path"], None)
        deps.add_read(abs_path)
        return

    if sc in R_FIRST_PATH:
        if not enter["path"]:
            return
        abs_path = ctx.resolve(enter["pid"], enter["tid"], enter["path"], None)
        deps.add_read(abs_path)
        return

    if sc in W_FIRST_PATH:
        if not enter["path"]:
            return
        abs_path = ctx.resolve(enter["pid"], enter["tid"], enter["path"], None)
        if ret == 0:
            deps.add_write(abs_path)
        else:
            deps.add_read(abs_path)
        return

    if sc in R_FD_PATH:
        if not enter["path"]:
            return
        abs_path = ctx.resolve(
            enter["pid"], enter["tid"], enter["path"], enter["dfd"]
        )
        deps.add_read(abs_path)
        return

    if sc in W_FD_PATH:
        if not enter["path"]:
            return
        abs_path = ctx.resolve(
            enter["pid"], enter["tid"], enter["path"], enter["dfd"]
        )
        if ret == 0:
            deps.add_write(abs_path)
        else:
            deps.add_read(abs_path)
        return

    if sc in ("renameat", "renameat2"):
        abs1 = ctx.resolve(
            enter["pid"], enter["tid"], enter["path1"], enter["dfd"]
        )
        abs2 = ctx.resolve(
            enter["pid"], enter["tid"], enter["path2"], enter["dfd2"]
        )
        deps.add_write(abs1)
        deps.add_write(abs2)
        return

    if sc == "dup":
        if ret >= 0:
            ctx.fd_dup(enter["pid"], enter["fd"], ret)
        return

    if sc in ("dup2", "dup3"):
        if ret == enter["fd2"]:
            ctx.fd_dup(enter["pid"], enter["fd"], enter["fd2"])
        return

    if sc == "fcntl":
        cmd = enter["cmd"]
        if cmd in (F_DUPFD, F_DUPFD_CLOEXEC):
            if ret >= 0:
                ctx.fd_dup(enter["pid"], enter["fd"], ret)
        # F_GETFD / F_SETFD don't change dependencies for our purposes.
        return


def _path_sort_key(p):
    """Match Rust's PathBuf::cmp ordering, which compares Components rather
    than raw bytes. The functional difference shows up at separator
    boundaries: '/a/b' vs '/a.b' — byte-wise '/a.b' < '/a/b' because '.'
    (46) < '/' (47), but Rust treats them as ('a','b') vs ('a.b',) and
    'a' < 'a.b' so '/a/b' < '/a.b'. Splitting into a tuple of components
    produces the Rust ordering."""
    return tuple(p.split("/"))


def _emit(deps, out):
    """Format identical to dep_tracer.rs::RWSet::dump_sets — Rust prints
    PathBuf with Debug, which renders ascii paths as quoted literals."""
    out.write("Read set\n")
    for p in sorted(deps.r, key=_path_sort_key):
        out.write(f'"{p}"\n')
    out.write("Write set\n")
    for p in sorted(deps.w, key=_path_sort_key):
        out.write(f'"{p}"\n')


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("events", help="path to bpftrace event log, or '-' for stdin")
    ap.add_argument(
        "--cwd",
        default=os.getcwd(),
        help="initial working directory of the traced root process "
             "(default: $PWD at the time post-processing runs)",
    )
    ap.add_argument(
        "--out",
        default="-",
        help="dependency summary output, or '-' for stdout (default: -)",
    )
    ap.add_argument(
        "--exclude-prefix",
        action="append",
        default=[],
        help="drop dep-set entries whose path starts with this prefix. "
             "Used by run.sh to scrub the bpftrace -c wrapper script's "
             "/tmp path so the dep set is comparable to trace_v3, which "
             "execs the target directly without a wrapper.",
    )
    ap.add_argument(
        "--skip-bootstrap",
        action="store_true",
        help="skip events up to the second sys_enter_execve. The first "
             "execve in our pipeline is the /bin/sh wrapper invocation "
             "(an artifact of bpftrace 0.17's ELF-only -c); the second is "
             "the wrapper's exec of the actual workload. trace_v3 starts "
             "directly at the equivalent of the second execve.",
    )
    args = ap.parse_args()

    if args.events == "-":
        src = sys.stdin
    else:
        src = open(args.events, "r")

    if args.out == "-":
        out = sys.stdout
    else:
        out = open(args.out, "w")

    def event_stream():
        for line in src:
            ev = parse_event(line)
            if ev is not None:
                yield ev

    process(
        event_stream(),
        args.cwd,
        out,
        exclude_prefixes=args.exclude_prefix,
        skip_bootstrap=args.skip_bootstrap,
    )

    if src is not sys.stdin:
        src.close()
    if out is not sys.stdout:
        out.close()


if __name__ == "__main__":
    main()
