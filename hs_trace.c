#include <sys/wait.h>

#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "hs_trace.h"
#include "hs_trace.skel.h"

static int
libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level >= LIBBPF_DEBUG)
		return 0;

	return vfprintf(stderr, format, args);
}

int
handle_event(void *ctx, void *data, long unsigned int data_sz)
{
	char *m = data;

	printf("%s\n", m);

	return 0;
}

// void
// lost_event(void *ctx, int cpu, long long unsigned int data_sz)
// {
// 	printf("lost event\n");
// }

int
main(int argc, char *argv[])
{
	struct hs_trace_bpf *skel;
	int err;
	struct ring_buffer *rb = NULL;

	libbpf_set_print(libbpf_print_fn);
	if (argc < 2) {
		fprintf(stderr, "usage: hs_trace <cmd>\n");
		return EXIT_FAILURE;
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

		int sig;
		if (sigwait(&set, &sig) != 0) {
			fprintf(stderr, "sigwait: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}

		execvp(argv[1], argv + 1);
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

	fprintf(stderr, "now allow child %d to start. send SIGUSR1\n", pid);
	kill(pid, SIGUSR1);

	fprintf(stderr, "Now we wait\n");
	int exit_status;
	if (wait(&exit_status) == -1) {
		fprintf(stderr, "Failed to wait for child\n");
	}

	fprintf(stderr, "done waiting\n");

	for (;;) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		// Ctrl-C gives -EINTR
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
		ring_buffer__consume(rb);
	}

	ring_buffer__free(rb);
	hs_trace_bpf__destroy(skel);
	return EXIT_SUCCESS;
}
