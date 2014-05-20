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

#include <netinet/in.h>
#include <signal.h>

#include "crash.h"
#include "platform.h"

void *platform_arg(mcontext_t *mctx, int param)
{
	if(param < 4) {
		return (void *)(mctx->regs[4 + param] & 0xffffffff);
	} else {
		unsigned long *stack;
		stack = (unsigned long *)(mctx->regs[30] & 0xffffffff);
		return (void *)stack[4 + (param - 4)];
	}
}

int platform_set_return_value(mcontext_t *mctx, void *value)
{
	mctx->regs[2] = value;
	return 0;
}

int platform_perform_return(mcontext_t *mctx)
{
	mctx->pc = mctx->regs[31];
	return 0;
}

int platform_continue_execution(mcontext_t *mctx, int idx)
{
	int top, bottom;

	top = (detours[idx].orig >> 16) & 0xffff;
	bottom = (detours[idx].orig) & 0xffff;

	if(top != 0x3c1c) {
		printf("I don't know how to handle detour %d\n", idx);
		crash();
	}

	// emulate lui gp modification
	mctx->regs[28] = (bottom << 16);

	mctx->pc += 4;

	return 0;
}

