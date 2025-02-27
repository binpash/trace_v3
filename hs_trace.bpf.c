#define KERNEL
#include "hs_trace.h"

#include <asm/unistd.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/limits.h>

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024);
} output SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__type(key, struct file_access_t);
// 	__type(value, struct unique_file_t);
// 	__uint(max_entries, 10240);
// } file_map SEC(".maps");
//
// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__type(key, struct unique_file_t);
// 	__type(value, struct file_access_t);
// 	__uint(max_entries, 10240);
// } file_map_mirror SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct unique_file_t);
	__type(value, char[4096]);
	__uint(max_entries, 256);
} read_path_set SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct unique_file_t);
	__type(value, char[4096]);
	__uint(max_entries, 256);
} write_path_set SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__type(value, long int);
	__uint(max_entries, 1);
} syscall_nr_queue SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, pid_t);
	__type(value, int);
	__uint(max_entries, 1024);
} pids SEC(".maps");

SEC("tp_btf/sys_enter")

int
BPF_PROG(hs_trace_sys_enter, struct pt_regs *regs, long syscall_id)
{
	pid_t pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	if (bpf_map_lookup_elem(&pids, &pid) == NULL) {
		return 0;
	}

	int fd = -1;
	char *path = NULL;
	enum rw_set_t set_type = UNKNOWN;

	switch (syscall_id) {
		// case __NR_clone:
	case __NR_exit:
		if (bpf_map_delete_elem(&pids, &pid) < 0) {
			bpf_printk("failed to remove pid\n");
		}
		break;
	case __NR_openat: /* individually */
		fd = (int)PT_REGS_PARM1_CORE(regs);
		path = (char *)PT_REGS_PARM2_CORE(regs);
		break;
	case __NR_execve: /* r_first_path_set */
	case __NR_statfs:
	case __NR_getxattr:
	case __NR_lgetxattr:
		// case __NR_stat:
		// case __NR_lstat:
		// case __NR_access:
		// case __NR_readlink:
		path = (char *)PT_REGS_PARM1_CORE(regs);
		set_type = READ_SET;
		break;
	case __NR_truncate: /* w_first_path_set */
	case __NR_acct:
		// case __NR_mkdir:
		// case __NR_rmdir:
		// case __NR_creat:
		// case __NR_chmod:
		// case __NR_chown:
		// case __NR_lchown:
		// case __NR_utime:
		// case __NR_utimes:
		// case __NR_mknod:
		// case __NR_unlink:
		path = (char *)PT_REGS_PARM1_CORE(regs);
		set_type = WRITE_SET;
		break;
	case __NR_newfstatat: /* r_fd_path_set */
	case __NR_statx:
	case __NR_name_to_handle_at:
	case __NR_readlinkat:
	case __NR_faccessat:
	case __NR_faccessat2:
	case __NR_execveat:
		fd = (int)PT_REGS_PARM1_CORE(regs);
		path = (char *)PT_REGS_PARM2_CORE(regs);
		set_type = READ_SET;
		break;
	case __NR_linkat: /* w_fd_path_set */
	case __NR_unlinkat:
	case __NR_utimensat:
	case __NR_mkdirat:
	case __NR_mknodat:
	case __NR_fchownat:
	case __NR_fchmodat:
		// case __NR_futimeat:
		fd = (int)PT_REGS_PARM1_CORE(regs);
		path = (char *)PT_REGS_PARM2_CORE(regs);
		set_type = WRITE_SET;
		break;
	default:
		return 0;
	}

	bpf_printk("sys_enter called on %ld\n", syscall_id);

	struct syscall_info_t *info =
		bpf_ringbuf_reserve(&output, sizeof(struct syscall_info_t), 0);
	if (info == NULL) {
		return 0;
	}
	info->type = SYS_ENTER;
	info->enter.syscall_nr = syscall_id;
	info->enter.arg1 = PT_REGS_PARM1_CORE(regs);
	info->enter.arg2 = PT_REGS_PARM2_CORE(regs);
	info->enter.arg3 = PT_REGS_PARM3_CORE(regs);
	info->enter.arg4 = PT_REGS_PARM4_CORE(regs);
	info->enter.arg5 = PT_REGS_PARM5_CORE(regs);
	info->enter.set_type = set_type;
	info->enter.pid = pid;
	info->enter.fd = fd;
	bpf_probe_read_user_str(&info->enter.path, sizeof(info->enter.path), path);

	bpf_ringbuf_submit(info, 0);

	/*
	 * NOTE: according to https://docs.kernel.org/bpf/map_queue_stack.html
	 * with BPF_EXIST, oldest elem will be evicted. We should be good
	 * because enters and exits should be matched, but in the off chance they
	 * aren't, this should prevent us from missing a newer event.
	 */
	if (bpf_map_push_elem(&syscall_nr_queue, &syscall_id, BPF_EXIST) < 0) {
		bpf_printk("failed queue push\n");
		return 0;
	}

	return 0;
}

struct scratch_data {
	struct file_access_t access;
	struct unique_file_t file;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, 4);
	__uint(value_size, sizeof(struct scratch_data));
	__uint(max_entries, 1);
} scratch SEC(".maps");

SEC("tp_btf/sys_exit")

int
BPF_PROG(hs_trace_sys_exit, struct pt_regs *regs, long ret)
{
	pid_t pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	if (bpf_map_lookup_elem(&pids, &pid) == NULL) {
		return 0;
	}

	long syscall_id = -1;

	if (bpf_map_pop_elem(&syscall_nr_queue, &syscall_id) < 0) {
		/*
		 * This is okay. since we filter out some syscalls in
		 * sys_enter, not all sys_exits will be matched.
		 * so we pass the syscall nr along and if there exists one
		 * we know we got a syscall we want.
		 */
		return 0;
	}

	switch (syscall_id) {
	case __NR_clone:
	case __NR_exit:
	case __NR_openat: /* individually */
	case __NR_execve: /* r_first_path_set */
	case __NR_statfs:
	case __NR_getxattr:
	case __NR_lgetxattr:
	// case __NR_stat:
	// case __NR_lstat:
	// case __NR_access:
	// case __NR_readlink:
	case __NR_truncate: /* w_first_path_set */
	case __NR_acct:
	// case __NR_mkdir:
	// case __NR_rmdir:
	// case __NR_creat:
	// case __NR_chmod:
	// case __NR_chown:
	// case __NR_lchown:
	// case __NR_utime:
	// case __NR_utimes:
	// case __NR_mknod:
	// case __NR_unlink:
	case __NR_newfstatat: /* r_fd_path_set */
	case __NR_statx:
	case __NR_name_to_handle_at:
	case __NR_readlinkat:
	case __NR_faccessat:
	case __NR_faccessat2:
	case __NR_execveat:
	case __NR_linkat: /* w_fd_path_set */
	case __NR_unlinkat:
	case __NR_utimensat:
	case __NR_mkdirat:
	case __NR_mknodat:
	case __NR_fchownat:
	case __NR_fchmodat:
		// case __NR_futimeat:
		break;
	default:
		return 0;
	}

	struct syscall_info_t *info =
		bpf_ringbuf_reserve(&output, sizeof(struct syscall_info_t), 0);
	if (info == NULL) {
		return 0;
	}
	info->type = SYS_EXIT;
	info->exit.ret = ret;
	bpf_ringbuf_submit(info, 0);

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
