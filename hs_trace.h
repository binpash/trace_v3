#ifdef USER
#include <sys/types.h>
#include <unistd.h>
#else
#include "vmlinux.h"
#endif

#ifndef _HS_TRACE_H_
#define _HS_TRACE_H_

struct user_msg_t {
	char message[12];
};

struct file_access_t {
	pid_t pid;
	int fd;
};

struct unique_file_t {
	dev_t dev;
	ino_t ino;
};

enum rw_set_t {
	READ_SET,
	WRITE_SET,
	UNKNOWN_SET,
};

struct sys_enter_info_t {
	long int syscall_nr;
	long int arg1;
	long int arg2;
	long int arg3;
	long int arg4;
	long int arg5;
	enum rw_set_t set_type;
	int pid;
	int fd; // for -at syscalls: could be AT_FDCWD
	char path[4096];
};

struct sys_exit_info_t {
	long int ret;
};

enum syscall_event_type {
	SYS_ENTER,
	SYS_EXIT
};

struct syscall_event_t {
	enum syscall_event_type type;

	union {
		struct sys_enter_info_t enter;
		struct sys_exit_info_t exit;
	};
};

struct syscall_info_t {
	struct sys_enter_info_t enter;
	struct sys_exit_info_t exit;
};

struct data_t {
	int pid;
	int uid;
	char command[16];
	char message[12];
	char path[16];
};

#endif /* _HS_TRACE_H_ */
