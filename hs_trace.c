#define _GNU_SOURCE
#define USER
#include "hs_trace.h"

#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include <asm/unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hs_trace.skel.h"

static int
libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level >= LIBBPF_DEBUG)
		return 0;

	return vfprintf(stderr, format, args);
}

struct hs_trace_bpf *skel;

volatile sig_atomic_t running = true;

void
construct_path_at(pid_t pid, int fd, const char *restrict path,
                  char *restrict buf)
{
	char *base = NULL;
	char *base_fmt = NULL;
	if (path[0] == '/') { // if absolute path, just return it!
		strcpy(buf, path);
		return;
	} else if (fd == -1 || fd == AT_FDCWD) { // no fd given, or AT_FDCWD
		base_fmt = "/proc/%u/fd/cwd";
		if (asprintf(&base, base_fmt, pid) < 0) {
			return;
		}
	} else {
		base_fmt = "/proc/%u/fd/%u";
		if (asprintf(&base, base_fmt, pid, fd) < 0) {
			return;
		}
	}
	int n;
	if ((n = readlink(base, buf, PATH_MAX - 1)) < 0) {
		free(base);
		return;
	}
	free(base);
	buf[n] = '\0';
	// Try to remove trailing slashes
	if (buf[n - 1] == '/') {
		buf[n - 1] = '\0';
	}
	if (strlen(path) == 0) {
		return;
	}
	strcat(buf, "/");
	// NOTE (dan) 2025-04-17: we don't care about . and .. inside the path.
	// Python's os.path.join doesn't clean that up, so to keep behavior
	// consistent, we just concat
	if (n + 1 + strlen(path) < PATH_MAX) {
		strcat(buf, path);
	}
	// Try to remove trailing slashes
	if (buf[strlen(buf) - 1] == '/') {
		buf[strlen(buf) - 1] = '\0';
	}
}

void
update_rw_sets(enum rw_set_t set_type, char pathbuf[PATH_MAX])
{
	if (strncmp(pathbuf, "/tmp/pash_spec", 14) == 0 ||
	    strncmp(pathbuf, "/dev", 4) == 0) {
		return;
	}
	struct bpf_map *read_path_set = skel->maps.read_path_set;
	struct bpf_map *write_path_set = skel->maps.write_path_set;
	struct bpf_map *path_set = (set_type == READ_SET)    ? read_path_set
	                           : (set_type == WRITE_SET) ? write_path_set
	                                                     : NULL;
	if (path_set == NULL) { // ignore the event now. it probably isn't a read or
		                    // write update...
		return;
	}

	if (strncmp(pathbuf, "/dev/tty", 8) == 0) {
		return;
	}

	// if (bpf_map__update_elem(path_set, &f, sizeof(f), pathbuf,
	// 			 sizeof(pathbuf), BPF_EXIST) < 0) {
	// 	/* the elem exists already so there is a collision */
	// 	printf("collision in for path: %s\n", pathbuf);
	// }

	struct stat filedata;
	struct unique_file_t f;
	if (stat(pathbuf, &filedata) < 0) {
		fprintf(stderr, "stat %s: %s\n", pathbuf, strerror(errno));
		return;
	}
	f.dev = filedata.st_rdev;
	f.ino = filedata.st_ino;

	char buf[PATH_MAX] = {0};
	char buf2[PATH_MAX] = {0};
	strcpy(buf, pathbuf);
	fprintf(stderr, "attempting to add '%s'\n", buf);
	if (bpf_map__update_elem(path_set, &f, sizeof(f), &buf, PATH_MAX, BPF_ANY) <
	    0) {
		fprintf(stderr, "failed to add '%s'\n", buf);
		return;
	}

	// TODO (dan) 2025-04-17: change this to reverse search for the / and set it
	// to null.
	while (true) {
		snprintf(buf2, PATH_MAX - 1, "%s", dirname(buf));
		char *end = stpncpy(buf, buf2, strlen(buf2) + 1);
		*end = '\0';

		if (stat(buf, &filedata) < 0) {
			fprintf(stderr, "failed to stat\n");
			return;
		}
		f.dev = filedata.st_rdev;
		f.ino = filedata.st_ino;
		fprintf(stderr, "attempting to add '%s' to readset\n", buf);
		if (bpf_map__update_elem(read_path_set, &f, sizeof(f), &buf, PATH_MAX,
		                         BPF_ANY) < 0) {
			fprintf(stderr, "failed to add '%s' to readset\n", buf);
			return; // TODO: 2025-03-06 do I want to return??
		}

		if (strcmp(buf, "/") == 0) {
			return;
		}
	}
}

int
handle_event(void *ctx, void *data, long unsigned int data_sz)
{
	static struct syscall_info_t INFO = {0};
	struct syscall_event_t *s = data;
	char pathbuf[PATH_MAX] = {0};
	if (s->type == SYS_ENTER) {
		INFO.enter = s->enter;
		// early return from the enter call so we can gather the exit code info
		// before doing work
		return 0;
	} else {
		INFO.exit = s->exit;
	}
	printf("%ld(%p, %p, %p, %p, %p) ", INFO.enter.syscall_nr,
	       (void *)INFO.enter.arg1, (void *)INFO.enter.arg2,
	       (void *)INFO.enter.arg3, (void *)INFO.enter.arg4,
	       (void *)INFO.enter.arg5);
	printf("path from syscall was \"%s\"\n", INFO.enter.path);
	if (INFO.enter.fd == AT_FDCWD) {
		printf("AT_FDCWD\n");
	}
	// Return code of syscall
	printf("-> %ld\n", INFO.exit.ret);
	switch (INFO.enter.syscall_nr) {
#ifdef __NR_exit
	case __NR_exit:
		break;
#endif
#ifdef __NR_openat
	case __NR_openat: // TODO: handled individually
#endif
#ifdef __NR_open
	case __NR_open:
#endif
	{
		enum rw_set_t set_type;
		char ret_pathbuf[PATH_MAX] = {0};
		construct_path_at(INFO.enter.pid, INFO.enter.fd, INFO.enter.path,
		                  pathbuf);
		if (INFO.exit.ret < 0) {
			set_type = READ_SET;
			update_rw_sets(set_type, pathbuf);
		} else if (INFO.enter.flags & O_RDONLY) {
			set_type = READ_SET;
			update_rw_sets(set_type, pathbuf);
			// NOTE: use the return code, which is the fd returned!
			construct_path_at(INFO.enter.pid, INFO.exit.ret, "", ret_pathbuf);
			update_rw_sets(set_type, ret_pathbuf);
		} else {
			set_type = WRITE_SET;
			update_rw_sets(set_type, pathbuf);
			// NOTE: use the return code, which is the fd returned!
			construct_path_at(INFO.enter.pid, INFO.exit.ret, "", ret_pathbuf);
			update_rw_sets(set_type, ret_pathbuf);
		}
	} break;
#ifdef __NR_chdir
	case __NR_chdir:
		break;
#endif
#ifdef __NR_clone
	case __NR_clone:
		break;
#endif
#ifdef __NR_symlinkat
	case __NR_symlinkat:
		break;
#endif
#ifdef __NR_rename
	case __NR_rename:
		break;
#endif
	default:
		construct_path_at(INFO.enter.pid, INFO.enter.fd, INFO.enter.path,
		                  pathbuf);
		update_rw_sets(INFO.enter.set_type, pathbuf);
		break;
	}
	return 0;
}

void
lost_event(void *ctx, int cpu, long long unsigned int data_sz)
{
	printf("lost event\n");
}

void
dump_path_set(struct bpf_map *path_set)
{
	struct unique_file_t prev_key = {0};
	struct unique_file_t key = {0};
	int err = bpf_map__get_next_key(path_set, NULL, &key,
	                                sizeof(struct unique_file_t));
	if (err == -ENOENT) {
		printf("Empty\n");
		return;
	}
	while (true) {
		if (err == -ENOENT) {
			break;
		} else if (err < 0) {
			printf("err getting next key\n");
			return;
		}
		char buf[PATH_MAX] = {0};
		if (bpf_map__lookup_elem(path_set, &key, sizeof(struct unique_file_t),
		                         &buf, PATH_MAX, BPF_ANY) < 0) {
			return;
		}
		printf("%s\n", buf);
		prev_key = key;
		err = bpf_map__get_next_key(path_set, &prev_key, &key,
		                            sizeof(struct unique_file_t));
	}
}

void
dump_path_sets()
{
	printf("Read set:\n");
	dump_path_set(skel->maps.read_path_set);
	printf("Write set:\n");
	dump_path_set(skel->maps.write_path_set);
}

void
sigchld_handler(int signum)
{
	running = false;
}

int
main(int argc, char *argv[])
{
	int err;
	struct ring_buffer *rb = NULL;

	libbpf_set_print(libbpf_print_fn);
	if (argc < 2) {
		fprintf(stderr, "usage: hs_trace <cmd>\n");
		return EXIT_FAILURE;
	}

	// Register the signal handler for SIGCHLD
	struct sigaction sa;
	sa.sa_handler = sigchld_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		perror("sigaction");
		exit(1);
	}

	int pid, devnull;
	switch (pid = fork()) {
	case -1:
		fprintf(stderr, "Failed fork\n");
		return EXIT_FAILURE;
	case 0:
		devnull = open("/dev/null", O_WRONLY);
		dup2(devnull, STDOUT_FILENO);
		dup2(devnull, STDERR_FILENO);

		sigset_t set;
		sigemptyset(&set);
		sigaddset(&set, SIGUSR1);
		sigprocmask(SIG_BLOCK, &set, NULL);

		/* wait on parent to set up maps first */
		int sig;
		if (sigwait(&set, &sig) != 0) {
			fprintf(stderr, "sigwait: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}

		argv++;
		execvp(argv[0], argv);
		fprintf(stderr, "exec failed\n");
		exit(EXIT_FAILURE);
	default:
		break;
	}

	skel = hs_trace_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF object\n");
		return EXIT_FAILURE;
	}

	err = hs_trace_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		hs_trace_bpf__destroy(skel);
		return EXIT_FAILURE;
	}

	int val = 1;
	if (bpf_map__update_elem(skel->maps.pids, &pid, sizeof(pid), &val,
	                         sizeof(val), BPF_ANY) < 0) {
		fprintf(stderr, "Failed to update map buffer\n");
		hs_trace_bpf__destroy(skel);
		return EXIT_FAILURE;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.output), handle_event, NULL,
	                      NULL);
	if (!rb) {
		fprintf(stderr, "Failed to create ring buffer\n");
		hs_trace_bpf__destroy(skel);
		return EXIT_FAILURE;
	}

	/* starting child */
	kill(pid, SIGUSR1);
	fprintf(stderr, "now allow child %d to start. sent SIGUSR1\n", pid);

	while (running) {
		err = ring_buffer__poll(rb, 10 /* timeout, ms */);
		// Ctrl-C gives -EINTR
		if (err == -EINTR && running) {
			err = 0;
			break;
		}
		if (err < 0 && running) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

	int exit_status;
	if (wait(&exit_status) != pid) {
		fprintf(stderr, "wait: %s\n", strerror(errno));
	}

	dump_path_sets();

	ring_buffer__free(rb);
	hs_trace_bpf__destroy(skel);
	return EXIT_SUCCESS;
}
