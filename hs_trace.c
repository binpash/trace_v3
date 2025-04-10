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
update_rw_sets(struct syscall_info_t *s, char pathbuf[PATH_MAX])
{
	if (strncmp(pathbuf, "/tmp/pash_spec", 14) == 0 ||
	    strncmp(pathbuf, "/dev", 4) == 0) {
		return;
	}
	struct bpf_map *read_path_set = skel->maps.read_path_set;
	struct bpf_map *write_path_set = skel->maps.write_path_set;
	struct bpf_map *path_set = (s->enter.set_type == READ_SET) ? read_path_set
	                           : (s->enter.set_type == WRITE_SET)
	                               ? write_path_set
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
	struct syscall_info_t *s = data;
	char pathbuf[PATH_MAX] = {0};
	if (s->type == SYS_ENTER) {
		// printf("%ld(%p, %p, %p, %p, %p) ", s->enter.syscall_nr,
		//        (void *)s->enter.arg1, (void *)s->enter.arg2,
		//        (void *)s->enter.arg3, (void *)s->enter.arg4,
		//        (void *)s->enter.arg5);
		// printf("path from syscall was \"%s\"\n", s->enter.path);
		// if (s->enter.fd == AT_FDCWD) {
		// 	printf("AT_FDCWD\n");
		// }
		switch (s->enter.syscall_nr) {
#ifdef __NR_exit
		case __NR_exit:
			break;
#endif
#ifdef __NR_openat
		case __NR_openat: // TODO: handle this and other syscalls
			break;
#endif
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
#ifdef __NR_open
		case __NR_open:
			break;
#endif
#ifdef __NR_rename
		case __NR_rename:
			break;
#endif
		default:
			// TODO: probably need to differentiate between the syscall types
			// here too.
			// TODO: Need to handle AT_FDCWD correctly by reading the process
			// cwd...
			// NOTE: here we should have (fd, path), (AT_FDCWD, path) or
			// just (-1, path). path resolution for relative paths uses CWD by
			// default I think
			if (s->enter.fd != -1 && s->enter.fd != AT_FDCWD) {
				// NOTE: assume procfs links to canon paths

				// char linkpath[sizeof("/proc/%u/fd/%u") + 2 * sizeof(int) * 3]
				// = 	{0};
				char *linkpath;
				if (asprintf(&linkpath, "/proc/%u/fd/%u", s->enter.pid,
				             s->enter.fd) < 0) {
					return 0;
				}
				int n;
				if ((n = readlink(linkpath, pathbuf, PATH_MAX - 1)) < 0) {
					return 0;
				}
				pathbuf[n] = '\0';
				if (n + 1 + strlen(s->enter.path) < PATH_MAX) {
					strcat(pathbuf, "/");
					strcat(pathbuf, s->enter.path);
				}
			} else {
				// NOTE: Do canon for only AT_FDCWD and just path
				if (realpath(s->enter.path, pathbuf) == NULL) {
					fprintf(stderr, "failed to canonicalize path: %s\n",
					        s->enter.path);
					return 0;
				}
			}
			update_rw_sets(s, pathbuf);
			break;
		}
	} else {
		// Return code of syscall
		// printf("-> %ld\n", s->exit.ret);
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
