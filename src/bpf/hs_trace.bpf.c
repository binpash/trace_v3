#include "hs_trace.h"

#include "vmlinux.h"

#include <asm/unistd.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/limits.h>

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024 * BUFF_SIZE);
} output SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} missed_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, char[PATH_MAX]);
	__uint(max_entries, 2);
} paths SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 1024 * 1024);
} pipe_tracker SEC(".maps");

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
} pid_set SEC(".maps");

struct sys_enter_fcntl_args {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	// keep track of offset and size of each field
	// don't just use the types in the format file
	long int syscall_nr;
	unsigned long int fd;
	unsigned long int cmd;
	unsigned long int arg;
};

SEC("tracepoint/syscalls/sys_enter_fcntl")

int
BPF_PROG(hs_trace_enter_fcntl)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid & 0xFFFFFFFF;

	if (bpf_map_lookup_elem(&pid_set, &pid) == NULL) {
		return 0;
	}
	struct sys_enter_info_t *enter_fcntl;

	if ((enter_fcntl = bpf_ringbuf_reserve(
		 &output, sizeof(struct sys_enter_info_t), 0)) == NULL) {
		u32 key = 0;
		u32 *missed = bpf_map_lookup_elem(&missed_events, &key);
		if (missed) {
			__sync_fetch_and_add(missed, 1);
		}
		return 0;
	}
	enter_fcntl->pid_tgid = pid_tgid;
	enter_fcntl->syscall_nr =
	    ((struct sys_enter_fcntl_args *)ctx)->syscall_nr;
	enter_fcntl->event_type = ENTER_FCNTL;
	enter_fcntl->flags = 0;
	enter_fcntl->cmd = ((struct sys_enter_fcntl_args *)ctx)->cmd;
	enter_fcntl->arg = ((struct sys_enter_fcntl_args *)ctx)->arg;
	enter_fcntl->fd = ((struct sys_enter_fcntl_args *)ctx)->fd;
	enter_fcntl->fd2 = -1;
	enter_fcntl->path1_len = 0;
	enter_fcntl->path2_len = 0;
	bpf_ringbuf_submit(enter_fcntl, 0);
	return 0;
}

struct sys_enter_memfd_create_args {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int syscall_nr;
	const char *uname;
	unsigned int flags;
};

SEC("tracepoint/syscalls/sys_enter_memfd_create")

int
BPF_PROG(hs_trace_enter_memfd_create)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid & 0xFFFFFFFF;

	if (bpf_map_lookup_elem(&pid_set, &pid) == NULL) {
		return 0;
	}

	u32 key = 0;

	char *path1 = bpf_map_lookup_elem(&paths, &key);
	int len1 =
	    BPF_SNPRINTF(path1, PATH_MAX, "memfd:%s",
	                 ((struct sys_enter_memfd_create_args *)ctx)->uname);
	if (len1 > PATH_MAX) {
		len1 = PATH_MAX;
	}

	struct sys_enter_info_t *enter1;

	if ((enter1 = bpf_ringbuf_reserve(
		 &output, sizeof(struct sys_enter_info_t) + len1, 0)) == NULL) {
		u32 key = 0;
		u32 *missed = bpf_map_lookup_elem(&missed_events, &key);
		if (missed) {
			__sync_fetch_and_add(missed, 1);
		}

		return 0;
	}

	enter1->pid_tgid = pid_tgid;
	enter1->syscall_nr =
	    ((struct sys_enter_memfd_create_args *)ctx)->syscall_nr;
	enter1->flags = ((struct sys_enter_memfd_create_args *)ctx)->flags;
	enter1->event_type = ENTER_PATH1;
	enter1->cmd = ((struct sys_enter_fcntl_args *)ctx)->cmd;
	enter1->arg = ((struct sys_enter_fcntl_args *)ctx)->arg;
	enter1->fd = -1;
	enter1->fd2 = -1;
	enter1->path1_len = len1;
	enter1->path2_len = 0;

	BPF_SNPRINTF(enter1->pathbuf, len1, "memfd:%s",
	             ((struct sys_enter_memfd_create_args *)ctx)->uname);
	// __builtin_memcpy(enter1->pathbuf, path1, len1);

	bpf_ringbuf_submit(enter1, 0);
	return 0;
}

struct sys_enter_pipe2_args {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int id;      // syscall number
	int *fildes; // pipe fds
	long flags;  // flags
};

SEC("tracepoint/syscalls/sys_enter_pipe2")

int
BPF_PROG(hs_trace_create_pipe)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid & 0xFFFFFFFF;

	if (bpf_map_lookup_elem(&pid_set, &pid) == NULL) {
		return 0;
	}

	u64 ptr = (u64)((struct sys_enter_pipe2_args *)ctx)->fildes;
	if (bpf_map_update_elem(&pipe_tracker, &pid, &ptr, BPF_ANY) < 0) {
		// bpf_printk("failed to update pipe_tracker with pid %d\n",
		// pid);
		return 0;
	}

	return 0;
}

struct sys_exit_pipe2_args {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	int id;   // syscall number
	long ret; // return value
};

SEC("tracepoint/syscalls/sys_exit_pipe2")

int
BPF_PROG(hs_trace_create_pipe_exit)
{
	struct sys_enter_info_t *enter2;

	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid & 0xFFFFFFFF;
	if (bpf_map_lookup_elem(&pid_set, &pid) == NULL) {
		// //bpf_printk("pid %d is not in set\n", pid);
		return 0;
	}
	if (((struct sys_exit_pipe2_args *)ctx)->ret < 0) {
		return 0;
	}

	u64 *fds_pointers;
	if ((fds_pointers = bpf_map_lookup_elem(&pipe_tracker, &pid)) == NULL) {
		return 0;
	}

	int fds[2];
	bpf_probe_read_user(&fds, sizeof(fds), (void *)(*fds_pointers));

	bpf_map_delete_elem(&pipe_tracker, &pid);

	// Get inode for pseudo filename
	// bpf_rcu_read_lock();

	struct task_struct *t = (void *)bpf_get_current_task_btf();
	struct files_struct *files = BPF_CORE_READ(t, files);
	struct fdtable *fdtp = NULL;

	bpf_probe_read_kernel(&fdtp, sizeof(fdtp), &files->fdt);

	struct file **fd_array = NULL;
	bpf_probe_read_kernel(&fd_array, sizeof(fd_array), &fdtp->fd);

	int fd0 = fds[0];
	struct file *file0 = NULL;
	bpf_probe_read_kernel(&file0, sizeof(file0), &fd_array[fd0]);

	u64 ino = 0;
	ino = BPF_CORE_READ(file0, f_inode, i_ino);

	// bpf_rcu_read_unlock();

	u32 key0 = 0;

	char *path1 = bpf_map_lookup_elem(&paths, &key0);
	int len1 = BPF_SNPRINTF(path1, PATH_MAX, "pipe:[%d]", ino);

	if ((enter2 = bpf_ringbuf_reserve(
		 &output, sizeof(struct sys_enter_info_t) + 2 * len1, 0)) ==
	    NULL) {
		// //bpf_printk("FAILED to reserve space in ring buffer
		// for "
		//            "event_type == "
		//            "ENTER_PATH2\n");
		u32 key = 0;
		u32 *missed = bpf_map_lookup_elem(&missed_events, &key);
		if (missed) {
			__sync_fetch_and_add(missed, 1);
		}

		return 0;
	}

	enter2->pid_tgid = pid_tgid;
	enter2->syscall_nr = ((struct sys_exit_pipe2_args *)ctx)->id;
	enter2->flags = -1;
	enter2->event_type = ENTER_PATH2;
	enter2->cmd = 0;
	enter2->arg = 0;
	enter2->fd = fds[0];
	enter2->fd2 = fds[1];
	enter2->path1_len = len1;
	enter2->path2_len = len1;

	BPF_SNPRINTF(enter2->pathbuf, len1, "pipe:[%d]", ino);
	BPF_SNPRINTF(enter2->pathbuf + len1, len1, "pipe:[%d]", ino);
	// __builtin_memcpy(enter2->pathbuf, path1, len1);
	// __builtin_memcpy(enter2->pathbuf + len1, path1, len1);

	bpf_ringbuf_submit(enter2, 0);

	struct sys_exit_info_t *exit;
	if ((exit = bpf_ringbuf_reserve(&output, sizeof(struct sys_exit_info_t),
	                                0)) == NULL) {
		// //bpf_printk(
		//     "FAILED to reserve space in ring buffer for event_type ==
		//     " "SYS_EXIT\n");
		u32 key = 0;
		u32 *missed = bpf_map_lookup_elem(&missed_events, &key);
		if (missed) {
			__sync_fetch_and_add(missed, 1);
		}

		return 0;
	}
	exit->pid_tgid = pid_tgid;
	exit->ret = ((struct sys_exit_pipe2_args *)ctx)->ret;
	bpf_ringbuf_submit(exit, 0);

	return 0;
}


SEC("tp_btf/sched_process_fork")

int
BPF_PROG(hs_trace_process_fork, struct task_struct *parent,
         struct task_struct *child)
{
	u32 dummy_val = 1;
	u64 p_pid = parent->pid;
	u64 c_pid = child->pid;
	u64 p_tgid = parent->tgid;
	u64 c_tgid = child->tgid;
	u64 p_pid_tgid = (p_tgid << 32) | p_pid;
	u64 c_pid_tgid = (c_tgid << 32) | c_pid;


	// //bpf_printk("sched_process_fork called with parent %d and child
	// %d\n",
	//            p_pid, c_pid);
	if (bpf_map_lookup_elem(&pid_set, &p_pid) == NULL) {
		// //bpf_printk("parent pid %d not in set\n", p_pid);
		return 0;
	}
	if (bpf_map_update_elem(&pid_set, &c_pid, &dummy_val, BPF_ANY) < 0) {
		// bpf_printk("failed to update pid set with %d\n", c_pid);
		return 0;
	}
	bpf_printk("sched_process_fork called with parent %d and child %d\n",
	           p_pid, c_pid);
	// bpf_printk("update pid set with %d\n", c_pid);

	// struct sys_enter_info0_t *enter0;
	// if ((enter0 = bpf_ringbuf_reserve(
	// 	 &output, sizeof(struct sys_enter_info0_t), 0)) == NULL) {
	// 	// //bpf_printk(
	// 	//     "FAILED to reserve space in ring buffer for event_type ==
	// 	//     " "SYS_ENTER0\n");
	// 	u32 key = 0;
	// 	u32 *missed = bpf_map_lookup_elem(&missed_events, &key);
	// 	if (missed) {
	// 		__sync_fetch_and_add(missed, 1);
	// 	}
	// 	return 0;
	// }
	// enter0->pid_tgid = p_pid_tgid;
	// enter0->syscall_nr = __NR_clone;
	// enter0->flags = 0;
	// bpf_ringbuf_submit(enter0, 0);

	// struct sys_exit_info_t *exit;
	// if ((exit = bpf_ringbuf_reserve(&output, sizeof(struct
	// sys_exit_info_t),
	//                                 0)) == NULL) {
	// 	// //bpf_printk(
	// 	//     "FAILED to reserve space in ring buffer for event_type ==
	// 	//     " "SYS_EXIT\n");
	// 	u32 key = 0;
	// 	u32 *missed = bpf_map_lookup_elem(&missed_events, &key);
	// 	if (missed) {
	// 		__sync_fetch_and_add(missed, 1);
	// 	}
	//
	// 	return 0;
	// }
	// exit->pid_tgid = p_pid_tgid;
	// exit->ret = c_pid_tgid;
	// bpf_ringbuf_submit(exit, 0);
	return 0;
}

SEC("tp_btf/sched_process_exit")

int
BPF_PROG(hs_trace_process_exit, struct task_struct *p)
{
	u32 pid = p->pid;
	if (bpf_map_delete_elem(&pid_set, &pid) < 0) {
		// bpf_printk("failed to delete %d from pid set\n", pid);
		return 0;
	}
	// bpf_printk("removed %d from pid set\n", pid);
	return 0;
}

SEC("tp_btf/sys_enter")

int
BPF_PROG(hs_trace_sys_enter, struct pt_regs *regs, long syscall_id)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid & 0xFFFFFFFF;
	if (bpf_map_lookup_elem(&pid_set, &pid) == NULL) {
		// //bpf_printk("pid %d is not in set\n", pid);
		return 0;
	}

	int fd = -1;
	int fd2 = -1;
	char *pathptr1 = NULL;
	char *pathptr2 = NULL;
	unsigned int flags = 0;
	unsigned long int arg = 0;
	enum sys_enter_event_type_t event_type;

	switch (syscall_id) {
#ifdef __NR_openat
	case __NR_openat: /* individually */
		fd = (int)PT_REGS_PARM1_CORE(regs);
		pathptr1 = (char *)PT_REGS_PARM2_CORE(regs);
		flags = (int)PT_REGS_PARM3_CORE(regs);
		event_type = ENTER_PATH1;
		break;
#endif
#ifdef __NR_openat2
	case __NR_openat2: /* individually */
		fd = (int)PT_REGS_PARM1_CORE(regs);
		pathptr1 = (char *)PT_REGS_PARM2_CORE(regs);
		flags = (int)PT_REGS_PARM3_CORE(regs);
		event_type = ENTER_PATH1;
		break;
#endif
#ifdef __NR_open
	case __NR_open:
		pathptr1 = (char *)PT_REGS_PARM1_CORE(regs);
		flags = (int)PT_REGS_PARM2_CORE(regs);
		event_type = ENTER_PATH1;
		break;
#endif
#ifdef __NR_chdir
	case __NR_chdir:
		pathptr1 = (char *)PT_REGS_PARM1_CORE(regs);
		event_type = ENTER_PATH1;
		break;
#endif
#ifdef __NR_symlinkat
	case __NR_symlinkat:
		fd = (int)PT_REGS_PARM2_CORE(regs);
		pathptr1 = (char *)PT_REGS_PARM3_CORE(regs);
		event_type = ENTER_PATH1;
		break;
#endif
// #ifdef __NR_clone3
// 	case __NR_clone3:
// 		bpf_printk("CLONE3 CALLLED");
// 		//flags = (int)PT_REGS_PARM3_CORE(regs);
// 		event_type = SYS_ENTER0;
// 		break;
// #endif
// #ifdef __NR_clone
// 	case __NR_clone:
// 		bpf_printk("CLONE CALLLED");
// 		flags = (int)PT_REGS_PARM3_CORE(regs);
// 		event_type = SYS_ENTER0;
// 		break;
// #endif
#ifdef __NR_symlink
	case __NR_symlink:
		// NOTE: symlink only incurs a dependency for the symlink file
		// itself
		pathptr1 = (char *)PT_REGS_PARM2_CORE(regs);
		event_type = ENTER_PATH1;
		break;
#endif
#ifdef __NR_link
	case __NR_link:
		// NOTE: link incurs a dependency on both the original path and
		// the new path for the inode
		pathptr1 = (char *)PT_REGS_PARM1_CORE(regs);
		pathptr2 = (char *)PT_REGS_PARM2_CORE(regs);
		event_type = ENTER_PATH2;
		break;
#endif
#ifdef __NR_renameat2
	case __NR_renameat2:
#endif
		// TODO (dan 2025-05-27): flags for renameat2 might need special
		// handling
		flags = (int)PT_REGS_PARM5_CORE(regs);
		// FALLTHROUGH
#ifdef __NR_renameat
	case __NR_renameat:
#endif
		fd = (int)PT_REGS_PARM1_CORE(regs);
		fd2 = (int)PT_REGS_PARM3_CORE(regs);
		pathptr1 = (char *)PT_REGS_PARM2_CORE(regs);
		pathptr2 = (char *)PT_REGS_PARM4_CORE(regs);
		event_type = ENTER_PATH2;
		break;
#ifdef __NR_rename
	case __NR_rename:
		pathptr1 = (char *)PT_REGS_PARM1_CORE(regs);
		pathptr2 = (char *)PT_REGS_PARM2_CORE(regs);
		event_type = ENTER_PATH2;
		break;
#endif
#ifdef __NR_inotify_add_watch
	case __NR_inotify_add_watch:
		pathptr1 = (char *)PT_REGS_PARM2_CORE(regs);
		event_type = ENTER_PATH1;
		break;
#endif
#ifdef __NR_dup2
	case __NR_dup2:
		// FALLTHROUGH
#endif
#ifdef __NR_dup3
	case __NR_dup3:
		fd = (int)PT_REGS_PARM1_CORE(regs);
		fd2 = (int)PT_REGS_PARM2_CORE(regs);
		event_type = ENTER_PATH2;
		break;
#endif
#ifdef __NR_dup
	case __NR_dup:
		fd = (int)PT_REGS_PARM1_CORE(regs);
		event_type = ENTER_PATH1;
		break;
#endif
// #ifdef __NR_close
// 	case __NR_close:
// 		fd = (int)PT_REGS_PARM1_CORE(regs);
// 		event_type = ENTER_PATH1;
// 		break;
// #endif
#ifdef __NR_fcntl
	case __NR_fcntl:
		// TODO: COMPLETE
		fd = (int)PT_REGS_PARM1_CORE(regs);
		flags = (unsigned int)PT_REGS_PARM2_CORE(regs);
		arg = PT_REGS_PARM3_CORE(regs);
		event_type = ENTER_FCNTL;
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
		pathptr1 = (char *)PT_REGS_PARM1_CORE(regs);
		event_type = ENTER_PATH1;
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
		pathptr1 = (char *)PT_REGS_PARM1_CORE(regs);
		event_type = ENTER_PATH1;
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
		pathptr1 = (char *)PT_REGS_PARM2_CORE(regs);
		event_type = ENTER_PATH1;
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
		pathptr1 = (char *)PT_REGS_PARM2_CORE(regs);
		event_type = ENTER_PATH1;
		break;
	default:
		// ignore
		return 0;
	}

	bpf_printk("sys_enter called on %ld\n", syscall_id);

	struct sys_enter_info_t *enter;

	u32 key0 = 0;
	u32 key1 = 1;
	char *path1 = bpf_map_lookup_elem(&paths, &key0);
	long len1 = 0;
	if (pathptr1 != NULL) {
		bpf_probe_read_user_str(path1, PATH_MAX, pathptr1);
	}
	char *path2 = bpf_map_lookup_elem(&paths, &key1);
	long len2 = 0;
	if (pathptr2 != NULL) {
		bpf_probe_read_user_str(path2, PATH_MAX, pathptr2);
	}

	if ((enter = bpf_ringbuf_reserve(
		 &output, sizeof(struct sys_enter_info_t) + len1 + len2, 0)) ==
	    NULL) {
		// //bpf_printk("FAILED to reserve space in ring buffer
		// for "
		//            "event_type == "
		//            "ENTER_PATH2\n");
		u32 key = 0;
		u32 *missed = bpf_map_lookup_elem(&missed_events, &key);
		if (missed) {
			__sync_fetch_and_add(missed, 1);
		}

		return 0;
	}

	enter->pid_tgid = pid_tgid;
	enter->syscall_nr = syscall_id;
	enter->event_type = event_type;
	enter->flags = flags;
	enter->cmd = 0;
	enter->arg = 0;
	enter->fd = fd;
	enter->fd2 = fd2;
	enter->path1_len = len1;
	enter->path2_len = len2;

	bpf_probe_read_user_str(enter->pathbuf, len1, pathptr1);
	bpf_probe_read_user_str(enter->pathbuf + len1, len2, pathptr2);
	// __builtin_memcpy(enter->pathbuf, path1, len1);
	// __builtin_memcpy(enter->pathbuf + len1, path2, len2);

	bpf_ringbuf_submit(enter, 0);

	return 0;
}

struct sys_exit_args {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	long id;  // syscall number
	long ret; // return value
};

SEC("tracepoint/raw_syscalls/sys_exit")

int
BPF_PROG(hs_trace_sys_exit)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid & 0xFFFFFFFF;
	if (bpf_map_lookup_elem(&pid_set, &pid) == NULL) {
		return 0;
	}
	long syscall_id = ((struct sys_exit_args *)ctx)->id;

	// //bpf_printk("sys_exit event for syscall %ld\n", syscall_id);

	switch (syscall_id) {
#ifdef __NR_clone
	case __NR_clone:
		if (((struct sys_exit_args *)ctx)->ret > 0) {
			return 0;
		};
#endif
#ifdef __NR_openat
	case __NR_openat: /* individually */
#endif
#ifdef __NR_openat2
	case __NR_openat2: /* individually */
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
#ifdef __NR_dup2
	case __NR_dup2:
#endif
#ifdef __NR_dup3
	case __NR_dup3:
#endif
#ifdef __NR_dup
	case __NR_dup:
#endif
// #ifdef __NR_close
// 	case __NR_close:
// #endif
#ifdef __NR_fcntl
	case __NR_fcntl:
#endif
#ifdef __NR_memfd_create
	case __NR_memfd_create:
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

	////bpf_printk("sys_exit called on %ld\n", syscall_id);

	struct sys_exit_info_t *exit;
	if ((exit = bpf_ringbuf_reserve(&output, sizeof(struct sys_exit_info_t),
	                                0)) == NULL) {
		// //bpf_printk(
		//     "FAILED to reserve space in ring buffer for event_type ==
		//     " "SYS_EXIT\n");
		u32 key = 0;
		u32 *missed = bpf_map_lookup_elem(&missed_events, &key);
		if (missed) {
			__sync_fetch_and_add(missed, 1);
		}
		// bpf_printk("Syscall failed %ld\n", syscall_id);

		return 0;
	}
	exit->pid_tgid = pid_tgid;
	exit->ret = ((struct sys_exit_args *)ctx)->ret;
	bpf_ringbuf_submit(exit, 0);

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
