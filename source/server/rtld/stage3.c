#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <dlfcn.h>

long syscall(long n, ...)
{
	(*(unsigned char *)NULL) = 0;
}

int main(int argc, char **argv)
{
	void *x;
	void *y;
	// printf("hello world!\n");
	x = dlopen("./vdso.so", RTLD_NOW);
	y = dlsym(x, "sassy_syscall");
	printf("it's at 0x%08x\n", y);
}
