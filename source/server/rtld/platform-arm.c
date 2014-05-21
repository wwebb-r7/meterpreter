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
	unsigned long *stack;

	switch(param) {
		case 0: return (void *)(mctx->arm_r0);
		case 1: return (void *)(mctx->arm_r1);
		case 2: return (void *)(mctx->arm_r2);
		case 3: return (void *)(mctx->arm_r3);
		default:
			stack = (unsigned long *)(mctx->arm_sp);
			return (void *)stack[(param-4)];
	}
}

int platform_set_return_value(mcontext_t *mctx, void *value)
{
	mctx->arm_r0 = value;
	return 0;
}

int platform_perform_return(mcontext_t *mctx)
{
	mctx->arm_pc = mctx->arm_lr;
	mctx->arm_ip = mctx->arm_ip;
	return 0;
}

int platform_continue_execution(mcontext_t *mctx, int idx)
{
	int top, bottom;
	unsigned long *sp;

	top = (detours[idx].orig >> 16) & 0xffff;
	bottom = (detours[idx].orig) & 0xffff;

#if 0
0002453c <open>:
   2453c:	e92d000e 	push	{r1, r2, r3}
0006444c <__mmap>:
   6444c:	e92d4830 	push	{r4, r5, fp, lr}
000827b8 <fstat>:
   827b8:	e92d4800 	push	{fp, lr}
000a7d34 <close>:
   a7d34:	e92d4800 	push	{fp, lr}
000a95f0 <pread>:
   a95f0:	e92d4810 	push	{r4, fp, lr}
000a97d8 <read>:
   a97d8:	e92d4800 	push	{fp, lr}
#endif

	if(top != 0xe92d) {
		printf("I don't know how to handle detour %d\n", idx);
		crash();
	}

	sp = (unsigned long *)(mctx->arm_sp);

	switch(bottom) {
		/* XXX, we may consider properly decoding here */
		case 0x000e:
			sp--; *sp = mctx->arm_r3;
			sp--; *sp = mctx->arm_r2;
			sp--; *sp = mctx->arm_r1;
			break;
		case 0x4830:
			sp--; *sp = mctx->arm_lr;
			sp--; *sp = mctx->arm_fp;
			sp--; *sp = mctx->arm_r5;
			sp--; *sp = mctx->arm_r4;
			break;
		case 0x4800:
			sp--; *sp = mctx->arm_lr;
			sp--; *sp = mctx->arm_fp;
			break;
		case 0x4810:
			sp--; *sp = mctx->arm_lr;
			sp--; *sp = mctx->arm_fp;
			sp--; *sp = mctx->arm_r4;
			break;
		default:
			printf("Need to implement pushing for 0x%04x\n", bottom);
			break;
	}

	mctx->arm_sp = (unsigned long)(sp);
	mctx->arm_pc += 4;
	mctx->arm_ip += 4;

	return 0;
}

