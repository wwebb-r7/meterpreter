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

#if 0
  4005c3:       49 b9 66 66 66 66 66    movabs $0x6666666666666666,%r9
  4005ca:       66 66 66 
  4005cd:       49 b8 55 55 55 55 55    movabs $0x5555555555555555,%r8
  4005d4:       55 55 55 
  4005d7:       48 b9 44 44 44 44 44    movabs $0x4444444444444444,%rcx
  4005de:       44 44 44 
  4005e1:       48 ba 33 33 33 33 33    movabs $0x3333333333333333,%rdx
  4005e8:       33 33 33 
  4005eb:       48 be 22 22 22 22 22    movabs $0x2222222222222222,%rsi
  4005f2:       22 22 22 
  4005f5:       48 bf 11 11 11 11 11    movabs $0x1111111111111111,%rdi
  4005fc:       11 11 11 

  rest in stack

#endif
	switch(param) {
		case 0: return (void *)(mctx->gregs[REG_RDI]); break;
		case 1: return (void *)(mctx->gregs[REG_RSI]); break;
		case 2: return (void *)(mctx->gregs[REG_RDX]); break;
		case 3: return (void *)(mctx->gregs[REG_RCX]); break;
		case 4: return (void *)(mctx->gregs[REG_R8]); break;
		case 5: return (void *)(mctx->gregs[REG_R9]); break;
		default:
			sp = (unsigned long *)(mctx->gregs[REG_RSP]);
			return (void *)(sp[param-6]);
			break;
	}
}

int platform_set_return_value(mcontext_t *mctx, void *value)
{
	mctx->gregs[REG_RAX] = value;
	return 0;
}

int platform_perform_return(mcontext_t *mctx)
{
	unsigned long *stack;

	stack = (unsigned long *)(mctx->gregs[REG_RSP]);	
	mctx->gregs[REG_RIP] = stack[0];
	stack++;
	mctx->gregs[REG_RSP] = (unsigned long)stack;

	return 0;
}

int platform_continue_execution(mcontext_t *mctx, int idx)
{
	long top, bottom, offset;

	top = (detours[idx].orig >> 8) & 0xffffff;
	bottom = (detours[idx].orig) & 0xff;

	if(top != 0x9421ff) {
		printf("I don't know how to handle detour %d\n", idx);
		crash();
	}

#if 0
#endif

	offset = 256 - bottom;

	mctx->gregs[1] -= offset;
	mctx->gregs[32] += 4;

	return 0;
}

