#include "hs_trace.h"

#include "vmlinux.h"

#include <asm/unistd.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/limits.h>

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024);
} output SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 1);
} missed_events SEC(".maps");
// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__type(key, struct unique_file_t);
// 	__type(value, char[4096]);
// 	__uint(max_entries, 256);
// } read_path_set SEC(".maps");
//
// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__type(key, struct unique_file_t);
// 	__type(value, char[4096]);
// 	__uint(max_entries, 256);
// } write_path_set SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1024);
} tgid_set SEC(".maps");

enum syscall_event_type {
	SYS_ENTER0,
	SYS_ENTER1,
	SYS_ENTER2,
	SYS_EXIT
};

SEC("tp_btf/sched_process_fork")

int
BPF_PROG(hs_trace_process_fork, struct task_struct *parent,
         struct task_struct *child)
{
	u32 dummy_val = 1;
	u32 p_tgid = parent->tgid;
	u32 c_tgid = child->tgid;
	if (bpf_map_lookup_elem(&tgid_set, &p_tgid) == NULL) {
		return 0;
	}
	if (bpf_map_update_elem(&tgid_set, &c_tgid, &dummy_val, BPF_ANY) < 0) {
		bpf_printk("failed to update tgid set with %d\n", c_tgid);
		return 0;
	}
	bpf_printk("update tgid set with %d\n", c_tgid);
	return 0;
}

SEC("tp_btf/sched_process_exit")

int
BPF_PROG(hs_trace_process_exit, struct task_struct *p)
{
	u32 tgid = p->tgid;
	if (bpf_map_delete_elem(&tgid_set, &tgid) < 0) {
		bpf_printk("failed to delete %d from tgid set\n", tgid);
		return 0;
	}
	bpf_printk("remove %d from tgid set\n", tgid);
	return 0;
}

SEC("tp_btf/sys_enter")

int
BPF_PROG(hs_trace_sys_enter, struct pt_regs *regs, long syscall_id)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid >> 32;
	if (bpf_map_lookup_elem(&tgid_set, &tgid) == NULL) {
		return 0;
	}

	int fd = -1;
	int fd2 = -1;
	char *path = NULL;
	char *path2 = NULL;
	int flags = 0;
	enum syscall_event_type event_type;

	switch (syscall_id) {
#ifdef __NR_openat
	case __NR_openat: /* individually */
		fd = (int)PT_REGS_PARM1_CORE(regs);
		path = (char *)PT_REGS_PARM2_CORE(regs);
		flags = (int)PT_REGS_PARM3_CORE(regs);
		event_type = SYS_ENTER1;
		break;
#endif
#ifdef __NR_open
	case __NR_open:
		path = (char *)PT_REGS_PARM1_CORE(regs);
		flags = (int)PT_REGS_PARM2_CORE(regs);
		event_type = SYS_ENTER1;
		break;
#endif
#ifdef __NR_chdir
	case __NR_chdir:
		path = (char *)PT_REGS_PARM1_CORE(regs);
		event_type = SYS_ENTER1;
		break;
#endif
#ifdef __NR_symlinkat
	case __NR_symlinkat:
		fd = (int)PT_REGS_PARM2_CORE(regs);
		path = (char *)PT_REGS_PARM3_CORE(regs);
		event_type = SYS_ENTER1;
		break;
#endif
#ifdef __NR_symlink
	case __NR_symlink:
#endif
		// NOTE: symlink only incurs a dependency for the symlink file itself
		path = (char *)PT_REGS_PARM2_CORE(regs);
		event_type = SYS_ENTER1;
		break;
#ifdef __NR_link
	case __NR_link:
#endif
		// NOTE: link incurs a dependency on both the original path and the new
		// path for the inode
		path = (char *)PT_REGS_PARM1_CORE(regs);
		path2 = (char *)PT_REGS_PARM2_CORE(regs);
		event_type = SYS_ENTER2;
		break;
#ifdef __NR_renameat2
	case __NR_renameat2:
#endif
		// TODO (dan 2025-05-27): flags for renameat2 might need special
		// handling
		flags = (int)PT_REGS_PARM5_CORE(regs);
#ifdef __NR_renameat
	case __NR_renameat:
#endif
		fd = (int)PT_REGS_PARM1_CORE(regs);
		fd2 = (int)PT_REGS_PARM3_CORE(regs);
		path = (char *)PT_REGS_PARM2_CORE(regs);
		path2 = (char *)PT_REGS_PARM4_CORE(regs);
		event_type = SYS_ENTER2;
		break;
#ifdef __NR_rename
	case __NR_rename:
		path = (char *)PT_REGS_PARM1_CORE(regs);
		path2 = (char *)PT_REGS_PARM2_CORE(regs);
		event_type = SYS_ENTER2;
		break;
#endif
#ifdef __NR_inotify_add_watch
	case __NR_inotify_add_watch:
		path = (char *)PT_REGS_PARM2_CORE(regs);
		event_type = SYS_ENTER1;
		break;
#endif
#ifdef __NR_execve
	case __NR_execve: /* r_first_path_set */
#endif
#ifdef __NR_statfs
	case __NR_statfs:
#endif
#ifdef __NR_getxattr
	case __NR_getxattr:
#endif
#ifdef __NR_lgetxattr
	case __NR_lgetxattr:
#endif
#ifdef __NR_stat
	case __NR_stat:
#endif
#ifdef __NR_lstat
	case __NR_lstat:
#endif
#ifdef __NR_access
	case __NR_access:
#endif
#ifdef __NR_readlink
	case __NR_readlink:
#endif
		path = (char *)PT_REGS_PARM1_CORE(regs);
		event_type = SYS_ENTER1;
		break;
#ifdef __NR_truncate
	case __NR_truncate: /* w_first_path_set */
#endif
#ifdef __NR_acct
	case __NR_acct:
#endif
#ifdef __NR_mkdir
	case __NR_mkdir:
#endif
#ifdef __NR_rmdir
	case __NR_rmdir:
#endif
#ifdef __NR_creat
	case __NR_creat:
#endif
#ifdef __NR_chmod
	case __NR_chmod:
#endif
#ifdef __NR_chown
	case __NR_chown:
#endif
#ifdef __NR_lchown
	case __NR_lchown:
#endif
#ifdef __NR_utime
	case __NR_utime:
#endif
#ifdef __NR_utimes
	case __NR_utimes:
#endif
#ifdef __NR_mknod
	case __NR_mknod:
#endif
#ifdef __NR_unlink
	case __NR_unlink:
#endif
		path = (char *)PT_REGS_PARM1_CORE(regs);
		event_type = SYS_ENTER1;
		break;
#ifdef __NR_newfstatat
	case __NR_newfstatat: /* r_fd_path_set */
#endif
#ifdef __NR_statx
	case __NR_statx:
#endif
#ifdef __NR_name_to_handle_at
	case __NR_name_to_handle_at:
#endif
#ifdef __NR_readlinkat
	case __NR_readlinkat:
#endif
#ifdef __NR_faccessat
	case __NR_faccessat:
#endif
#ifdef __NR_faccessat2
	case __NR_faccessat2:
#endif
#ifdef __NR_execveat
	case __NR_execveat:
#endif
		fd = (int)PT_REGS_PARM1_CORE(regs);
		path = (char *)PT_REGS_PARM2_CORE(regs);
		event_type = SYS_ENTER1;
		break;
#ifdef __NR_linkat
	case __NR_linkat: /* w_fd_path_set */
#endif
#ifdef __NR_unlinkat
	case __NR_unlinkat:
#endif
#ifdef __NR_utimensat
	case __NR_utimensat:
#endif
#ifdef __NR_mkdirat
	case __NR_mkdirat:
#endif
#ifdef __NR_mknodat
	case __NR_mknodat:
#endif
#ifdef __NR_fchownat
	case __NR_fchownat:
#endif
#ifdef __NR_fchmodat
	case __NR_fchmodat:
#endif
#ifdef __NR_futimeat
	case __NR_futimeat:
#endif
		fd = (int)PT_REGS_PARM1_CORE(regs);
		path = (char *)PT_REGS_PARM2_CORE(regs);
		event_type = SYS_ENTER1;
		break;
	default:
		// bpf_printk("ignoring sys_enter event for syscall %ld\n", syscall_id);
		return 0;
	}

	bpf_printk("sys_enter called on %ld\n", syscall_id);

	struct sys_enter_info0_t *enter0;
	struct sys_enter_info1_t *enter1;
	struct sys_enter_info2_t *enter2;
	if (event_type == SYS_ENTER0) {
		if ((enter0 = bpf_ringbuf_reserve(
				 &output, sizeof(struct sys_enter_info0_t), 0)) == NULL) {
			bpf_printk("FAILED to reserve space in ring buffer for event_type == SYS_ENTER0\n");
			bpf_printk("FAILED to reserve space in ring buffer for event_type == SYS_ENTER1\n");
			u32 key = 0;
			u32 *missed = bpf_map_lookup_elem(&missed_events, &key);
			if(missed) {
				__sync_fetch_and_add(missed, 1);
			}
			
			return 0;
		}
		enter0->pid = pid_tgid;
		enter0->syscall_nr = syscall_id;
		enter0->flags = flags;
		bpf_ringbuf_submit(enter0, 0);
	} else if (event_type == SYS_ENTER1) {
		if ((enter1 = bpf_ringbuf_reserve(
				 &output, sizeof(struct sys_enter_info1_t), 0)) == NULL) {
			bpf_printk("FAILED to reserve space in ring buffer for event_type == SYS_ENTER1\n");
			u32 key = 0;
			u32 *missed = bpf_map_lookup_elem(&missed_events, &key);
			if(missed) {
				__sync_fetch_and_add(missed, 1);
			}
			
			return 0;
		}
		enter1->pid = pid_tgid;
		enter1->syscall_nr = syscall_id;
		enter1->flags = flags;
		enter1->fd = fd;
		bpf_probe_read_user_str(&enter1->path, sizeof(enter1->path), path);
		bpf_ringbuf_submit(enter1, 0);
	} else if (event_type == SYS_ENTER2) {
		if ((enter2 = bpf_ringbuf_reserve(
				 &output, sizeof(struct sys_enter_info2_t), 0)) == NULL) {
			bpf_printk("FAILED to reserve space in ring buffer for event_type == SYS_ENTER1\n");
			u32 key = 0;
			u32 *missed = bpf_map_lookup_elem(&missed_events, &key);
			if(missed) {
				__sync_fetch_and_add(missed, 1);
			}
			
			return 0;
		}
		enter2->pid = pid_tgid;
		enter2->syscall_nr = syscall_id;
		enter2->flags = flags;
		enter2->fd = fd;
		enter2->fd2 = fd2;
		bpf_probe_read_user_str(&enter2->path, sizeof(enter2->path), path);
		bpf_probe_read_user_str(&enter2->path2, sizeof(enter2->path2), path2);
		bpf_ringbuf_submit(enter2, 0);
	}

	return 0;
}

SEC("tp_btf/sys_exit")

int
BPF_PROG(hs_trace_sys_exit, struct pt_regs *regs, long ret)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tgid = pid_tgid >> 32;
	if (bpf_map_lookup_elem(&tgid_set, &tgid) == NULL) {
		return 0;
	}

	// TODO (dan 2025-05-27): figure out if these macros are correct!
#ifdef __aarch64__
	long syscall_id = regs->syscallno;
#elifdef __x86_64__
	long syscall_id = regs->orig_ax;
#endif
	// bpf_printk("sys_exit event for syscall %ld\n", syscall_id);

	switch (syscall_id) {
#ifdef __NR_openat
	case __NR_openat: /* individually */
#endif
#ifdef __NR_open
	case __NR_open:
#endif
#ifdef __NR_chdir
	case __NR_chdir:
#endif
#ifdef __NR_symlinkat
	case __NR_symlinkat:
#endif
#ifdef __NR_symlink
	case __NR_symlink:
#endif
#ifdef __NR_link
	case __NR_link:
#endif
#ifdef __NR_rename
	case __NR_rename:
#endif
#ifdef __NR_renameat
	case __NR_renameat:
#endif
#ifdef __NR_renameat2
	case __NR_renameat2:
#endif
#ifdef __NR_inotify_add_watch
	case __NR_inotify_add_watch:
#endif
#ifdef __NR_execve
	case __NR_execve: /* r_first_path_set */
#endif
#ifdef __NR_statfs
	case __NR_statfs:
#endif
#ifdef __NR_getxattr
	case __NR_getxattr:
#endif
#ifdef __NR_lgetxattr
	case __NR_lgetxattr:
#endif
#ifdef __NR_stat
	case __NR_stat:
#endif
#ifdef __NR_lstat
	case __NR_lstat:
#endif
#ifdef __NR_access
	case __NR_access:
#endif
#ifdef __NR_readlink
	case __NR_readlink:
#endif
#ifdef __NR_truncate
	case __NR_truncate: /* w_first_path_set */
#endif
#ifdef __NR_acct
	case __NR_acct:
#endif
#ifdef __NR_mkdir
	case __NR_mkdir:
#endif
#ifdef __NR_rmdir
	case __NR_rmdir:
#endif
#ifdef __NR_creat
	case __NR_creat:
#endif
#ifdef __NR_chmod
	case __NR_chmod:
#endif
#ifdef __NR_chown
	case __NR_chown:
#endif
#ifdef __NR_lchown
	case __NR_lchown:
#endif
#ifdef __NR_utime
	case __NR_utime:
#endif
#ifdef __NR_utimes
	case __NR_utimes:
#endif
#ifdef __NR_mknod
	case __NR_mknod:
#endif
#ifdef __NR_unlink
	case __NR_unlink:
#endif
#ifdef __NR_newfstatat
	case __NR_newfstatat: /* r_fd_path_set */
#endif
#ifdef __NR_statx
	case __NR_statx:
#endif
#ifdef __NR_name_to_handle_at
	case __NR_name_to_handle_at:
#endif
#ifdef __NR_readlinkat
	case __NR_readlinkat:
#endif
#ifdef __NR_faccessat
	case __NR_faccessat:
#endif
#ifdef __NR_faccessat2
	case __NR_faccessat2:
#endif
#ifdef __NR_execveat
	case __NR_execveat:
#endif
#ifdef __NR_linkat
	case __NR_linkat: /* w_fd_path_set */
#endif
#ifdef __NR_unlinkat
	case __NR_unlinkat:
#endif
#ifdef __NR_utimensat
	case __NR_utimensat:
#endif
#ifdef __NR_mkdirat
	case __NR_mkdirat:
#endif
#ifdef __NR_mknodat
	case __NR_mknodat:
#endif
#ifdef __NR_fchownat
	case __NR_fchownat:
#endif
#ifdef __NR_fchmodat
	case __NR_fchmodat:
#endif
#ifdef __NR_futimeat
	case __NR_futimeat:
#endif
		break;
	default:
		return 0;
	}

	bpf_printk("sys_exit called on %ld\n", syscall_id);

	struct sys_exit_info_t *exit;
	if ((exit = bpf_ringbuf_reserve(&output, sizeof(struct sys_exit_info_t),
	                                0)) == NULL) {
		bpf_printk("FAILED to reserve space in ring buffer for event_type == SYS_ENTER1\n");
			u32 key = 0;
			u32 *missed = bpf_map_lookup_elem(&missed_events, &key);
			if(missed) {
				__sync_fetch_and_add(missed, 1);
			}
			
		return 0;
	}
	exit->pid = pid_tgid;
	exit->ret = ret;
	bpf_ringbuf_submit(exit, 0);

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
