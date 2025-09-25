#ifndef _HS_TRACE_H_
#define _HS_TRACE_H_

struct unique_file_t {
	int dev;
	int ino;
};

struct sys_enter_fcntl_info_t {
	long int pid_tgid;
	long int syscall_nr;
	int fd;
	unsigned int cmd;
	unsigned long arg;
};

struct sys_enter_info0_t {
	long int pid_tgid;
	long int syscall_nr;
	int flags; // for special handling: open*, clone, linkat, etc.
};

struct sys_enter_info1_t {
	long int pid_tgid;
	long int syscall_nr;
	int flags; // for special handling: open*, clone, linkat, etc.
	int fd;    // for -at syscalls: could be AT_FDCWD
	char path[1024];
};

struct sys_enter_info2_t {
	long int pid_tgid;
	long int syscall_nr;
	int flags; // for special handling: open*, clone, linkat, etc.
	int fd;    // for -at syscalls: could be AT_FDCWD
	int fd2;   // for renameat2 and linkat
	char path[1024];
	char path2[1024];
};

struct sys_exit_info_t {
	long int pid_tgid;
	long int ret;
};

#endif /* _HS_TRACE_H_ */
