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

enum sys_enter_event_type_t {
	ENTER_PATH0,
	ENTER_PATH1,
	ENTER_PATH2,
	ENTER_FCNTL,
};

struct sys_enter_info_t {
	long pid_tgid;
	long syscall_nr;
	enum sys_enter_event_type_t event_type;
	unsigned int flags; // for special handling: open*, clone, linkat, etc.
	unsigned int cmd;
	unsigned long arg;
	int fd;                 // for -at syscalls: could be AT_FDCWD
	int fd2;                // for renameat2 and linkat
	unsigned int path1_len; // including the terminating NUL, so 0 means
	                        // path is not used.
	unsigned int path2_len;
	char pathbuf[];
};

struct sys_exit_info_t {
	long int pid_tgid;
	long int ret;
};

#endif /* _HS_TRACE_H_ */
