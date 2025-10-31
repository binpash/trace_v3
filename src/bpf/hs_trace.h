#ifndef _HS_TRACE_H_
#define _HS_TRACE_H_

#ifndef HS_MAX_PATH
#define HS_MAX_PATH 1024 
#endif

#ifndef BUFF_SIZE
#define BUFF_SIZE 4 
#endif

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
	char path[HS_MAX_PATH];
};

struct sys_enter_info2_t {
	long int pid_tgid;
	long int syscall_nr;
	int flags; // for special handling: open*, clone, linkat, etc.
	int fd;    // for -at syscalls: could be AT_FDCWD
	int fd2;   // for renameat2 and linkat
	char path[HS_MAX_PATH];
	char path2[HS_MAX_PATH];
};

struct sys_exit_info_t {
	long int pid_tgid;
	long int ret;
};

#endif /* _HS_TRACE_H_ */
