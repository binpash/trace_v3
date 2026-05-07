#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

int main()
{
	volatile int sink; // prevent optimization

	for (int i = 0; i < 1000000; ++i) {
		int fd = openat(AT_FDCWD, "test10101010", 0);
		sink = fd;
	}
	printf("done\n");
    return 0;
}