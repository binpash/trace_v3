#ifndef _HS_TRACE_H_
#define _HS_TRACE_H_

#ifndef RINGBUF_SIZE
#define RINGBUF_SIZE 4
#endif

#ifndef RINGBUF_MAX_COUNT
#define RINGBUF_MAX_COUNT 64
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
	unsigned long pid_tgid;
	long syscall_nr;
	enum sys_enter_event_type_t event_type;
	unsigned int flags; // for special handling: open*, clone, linkat, etc.
	unsigned long cmd;
	unsigned long arg;
	int fd;                 // for -at syscalls: could be AT_FDCWD
	int fd2;                // for renameat2 and linkat
	unsigned int path1_len; // including the terminating NUL, so 0 means
	                        // path is not used.
	unsigned int path2_len;
	char pathbuf[];
};

struct sys_exit_info_t {
	unsigned long pid_tgid;
	long int ret;
};

#endif /* _HS_TRACE_H_ */
