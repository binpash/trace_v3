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

struct syscall_info_t {
	enum event_type {SYS_ENTER, SYS_EXIT} type;
	union {
		struct {
			uint64_t syscall_nr;
			uint64_t arg1;
			uint64_t arg2;
			uint64_t arg3;
			uint64_t arg4;
			uint64_t arg5;
			int fd; // for -at syscalls: could be AT_FDCWD
			char path[4096];
		} enter;
		struct {
			uint64_t ret;
		} exit;
	};
};

struct data_t {
   int pid;
   int uid;
   char command[16];
   char message[12];
   char path[16];
};

#endif /* _HS_TRACE_H_ */
