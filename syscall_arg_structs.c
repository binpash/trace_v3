struct open_args {

};
struct stat_args {

};
struct fstat_args {

};
struct lstat_args {

};
struct access_args {

};
struct execve_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
const char * filename;
const char *const * argv;
const char *const * envp;
};
struct truncate_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
const char * path;
long length;
};
struct getcwd_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
char * buf;
unsigned long size;
};
struct chdir_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
const char * filename;
};
struct rename_args {

};
struct mkdir_args {

};
struct rmdir_args {

};
struct creat_args {

};
struct link_args {

};
struct unlink_args {

};
struct symlink_args {

};
struct readlink_args {

};
struct chmod_args {

};
struct chown_args {

};
struct lchown_args {

};
struct utime_args {

};
struct mknod_args {

};
struct uselib_args {

};
struct statfs_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
const char * pathname;
struct statfs * buf;
};
struct fstatfs_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
unsigned int fd;
struct statfs * buf;
};
struct pivotroot_args {

};
struct chroot_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
const char * filename;
};
struct acct_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
const char * name;
};
struct mount_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
char * dev_name;
char * dir_name;
char * type;
unsigned long flags;
void * data;
};
struct umount2_args {

};
struct swapon_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
const char * specialfile;
int swap_flags;
};
struct swapoff_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
const char * specialfile;
};
struct quotactl_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
unsigned int cmd;
const char * special;
qid_t id;
void * addr;
};
struct setxattr_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
const char * pathname;
const char * name;
const void * value;
size_t size;
int flags;
};
struct lsetxattr_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
const char * pathname;
const char * name;
const void * value;
size_t size;
int flags;
};
struct getxattr_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
const char * pathname;
const char * name;
void * value;
size_t size;
};
struct lgetxattr_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
const char * pathname;
const char * name;
void * value;
size_t size;
};
struct listxattr_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
const char * pathname;
char * list;
size_t size;
};
struct llistxattr_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
const char * pathname;
char * list;
size_t size;
};
struct removexattr_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
const char * pathname;
const char * name;
};
struct lremovexattr_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
const char * pathname;
const char * name;
};
struct utimes_args {

};
struct inotify_add_watch_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
int fd;
const char * pathname;
u32 mask;
};
struct openat_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
int dfd;
const char * filename;
int flags;
umode_t mode;
};
struct mkdirat_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
int dfd;
const char * pathname;
umode_t mode;
};
struct mknodat_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
int dfd;
const char * filename;
umode_t mode;
unsigned int dev;
};
struct fchownat_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
int dfd;
const char * filename;
uid_t user;
gid_t group;
int flag;
};
struct futimesat_args {

};
struct newfstatat_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
int dfd;
const char * filename;
struct stat * statbuf;
int flag;
};
struct unlinkat_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
int dfd;
const char * pathname;
int flag;
};
struct renameat_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
int olddfd;
const char * oldname;
int newdfd;
const char * newname;
};
struct linkat_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
int olddfd;
const char * oldname;
int newdfd;
const char * newname;
int flags;
};
struct symlinkat_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
const char * oldname;
int newdfd;
const char * newname;
};
struct readlinkat_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
int dfd;
const char * pathname;
char * buf;
int bufsiz;
};
struct fchmodat_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
int dfd;
const char * filename;
umode_t mode;
};
struct faccessat_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
int dfd;
const char * filename;
int mode;
};
struct utimensat_time64_args {

};
struct fanotify_mark_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
int fanotify_fd;
unsigned int flags;
__u64 mask;
int dfd;
const char * pathname;
};
struct name_to_handle_at_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
int dfd;
const char * name;
struct file_handle * handle;
int * mnt_id;
int flag;
};
struct renameat2_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
int olddfd;
const char * oldname;
int newdfd;
const char * newname;
unsigned int flags;
};
struct execveat_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
int fd;
const char * filename;
const char *const * argv;
const char *const * envp;
int flags;
};
struct statx_args {
 unsigned short common_type;
unsigned char common_flags;
unsigned char common_preempt_count;
int common_pid;
int __syscall_nr;
int dfd;
const char * filename;
unsigned flags;
unsigned int mask;
struct statx * buffer;
};
