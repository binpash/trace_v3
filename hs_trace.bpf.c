#include "vmlinux.h"

#include <asm/unistd.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/limits.h>

#include "hs_trace.h"

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 32 * 4096);
} output SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct file_access_t);
	__type(value, struct unique_file_t);
	__uint(max_entries, 10240);
} file_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct unique_file_t);
	__type(value, struct file_access_t);
	__uint(max_entries, 10240);
} file_map_mirror SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__type(value, int);
	__uint(max_entries, 10240);
} queue SEC(".maps");

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
		return -1;
	}

	bpf_printk("sys_enter through\n");

	int fd = -1;
	char *path;

	switch (syscall_id) {
	case __NR_openat:
		fd = (int)PT_REGS_PARM1_CORE(regs);
		path = (char *)PT_REGS_PARM2_CORE(regs);
		bpf_printk("openat(%d, \"%s\", ...)\n", syscall_id, fd, path);
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
		bpf_printk("sys_%ld(%d, \"%s\", ...)\n", syscall_id, fd, path);
		break;
	default:
		return -1;
	}

	if (bpf_map_push_elem(&queue, &fd, BPF_ANY) < 0) {
		bpf_printk("failed to push to queue\n");
		return -1;
	}

	return 0;
}

struct scratch_data {
	struct file_access_t access;
	struct unique_file_t file;
	struct task_struct *task;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, 4);
	__uint(value_size, sizeof(struct scratch_data));
	__uint(max_entries, 1);
} scratch SEC(".maps");

SEC("tp_btf/sys_exit")

int
BPF_PROG(hs_trace_sys_exit, struct pt_regs *regs, long syscall_id)
{
	int z = 0;
	struct file_access_t *access = &((struct scratch_data *)bpf_map_lookup_percpu_elem(&scratch, &z, BPF_ANY))->access;
	struct unique_file_t *file = &((struct scratch_data *)bpf_map_lookup_percpu_elem(&scratch, &z, BPF_ANY))->file;
	struct task_struct **task = &((struct scratch_data *)bpf_map_lookup_percpu_elem(&scratch, &z, BPF_ANY))->task;

	access->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	if (bpf_map_lookup_elem(&pids, &access->pid) == NULL) {
		return -1;
	}

	access->fd = PT_REGS_RET(regs);

	int dirfd;
	if (bpf_map_pop_elem(&queue, &dirfd) < 0) {
		bpf_printk("bad queue access\n");
		return -1;
	}

	switch (syscall_id) {
	case __NR_openat:
		bpf_printk("sys_exit_openat -> %d\n", access->fd);
		break;
	default:
		return -1;
	}

	*task = (void *)bpf_get_current_task();

	file->dev = (*task)->files->fd_array[access->fd]->f_inode->i_rdev;
	file->ino = (*task)->files->fd_array[access->fd]->f_inode->i_ino;

	bpf_map_update_elem(&file_map, access, file, BPF_ANY);
	bpf_map_update_elem(&file_map_mirror, file, access, BPF_ANY);

	bpf_printk("dirfd for this call was %d\n", dirfd);

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
