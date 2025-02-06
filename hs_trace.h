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

struct data_t {
   int pid;
   int uid;
   char command[16];
   char message[12];
   char path[16];
};

#endif /* _HS_TRACE_H_ */
