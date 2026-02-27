#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>


#ifndef FREQ
#define FREQ 60
#endif

#ifndef SECS
#define SECS 10
#endif

int
main(int argc, char **argv)
{
	struct timespec t;
	t.tv_sec = 0;
	t.tv_nsec = 1000000000 / FREQ;
	for (int i = 0; i < SECS * FREQ; ++i) {
		int fd = openat(AT_FDCWD, "test10101010", 0);
		// nanosleep(&t, NULL);
	}
	printf("done\n");
}
