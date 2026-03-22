#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	if (argc < 2) {
		printf("usage: %s freq\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	struct timespec start, end;
	int iterations = 10000;
	volatile int sink; // prevent optimization

	clock_gettime(CLOCK_MONOTONIC, &start);

	for (int i = 0; i < iterations; i++) {
		sink = rand();
	}

	clock_gettime(CLOCK_MONOTONIC, &end);

	long long elapsed_ns = (end.tv_sec - start.tv_sec) * 1000000000LL +
	                       (end.tv_nsec - start.tv_nsec);

	printf("Total:   %lld ns over %d calls\n", elapsed_ns, iterations);
	printf("Per call: %.2f ns\n", (double)elapsed_ns / iterations);

	int ns_delay = ceil((double)elapsed_ns / iterations);

	int max_freq = 1000000000 / ns_delay;

	printf("maximum frequency is %d\n", max_freq);

	int freq = atoi(argv[1]);
	if (freq > max_freq) {
		freq = max_freq;
		printf("capping frequency to max frequency\n");
	}

	for (int i = 0; i < 5 * freq; ++i) {
		int fd = openat(AT_FDCWD, "test10101010", 0);

		for (int j = 0; j < max_freq / freq; ++j) {
			sink = rand();
		}
	}
	printf("done\n");
}
