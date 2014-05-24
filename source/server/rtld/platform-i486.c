#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/syscall.h>
#include <pthread.h>

#define _GNU_SOURCE

#include <netinet/in.h>
#include <signal.h>

#include "crash.h"
#include "platform.h"

void *platform_arg(mcontext_t *mctx, int param)
{
	unsigned long *sp;

	sp = (unsigned long *)(mctx->gregs[REG_ESP]);
	return (void *)(sp[param+1]);
}

int platform_set_return_value(mcontext_t *mctx, void *value)
{
	mctx->gregs[REG_EAX] = value;
	return 0;
}

int platform_perform_return(mcontext_t *mctx)
{
	unsigned long *stack;

	stack = (unsigned long *)(mctx->gregs[REG_ESP]);
	mctx->gregs[REG_EIP] = stack[0];
	stack++;
	mctx->gregs[REG_ESP] = (unsigned long)stack;

	return 0;
}

int platform_continue_execution(mcontext_t *mctx, int idx)
{
	long bottom;
	long *sp;

	bottom = (detours[idx].orig) & 0xff;

	if(bottom != 0x55) {
		printf("I don't know how to handle detour %d\n", idx);
		crash();
	}

	sp = mctx->gregs[REG_ESP];
	sp--;
	*sp = mctx->gregs[REG_EBP];
	mctx->gregs[REG_ESP] = (long) sp;

	return 0;
}

