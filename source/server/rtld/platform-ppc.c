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
	if(param < 8) {
		return (void *)(mctx->gregs[3 + param]);
	} else {
		unsigned long *sp;
		sp = (unsigned long *)(mctx->gregs[31]);
		return (void *)(sp[param-8]);
	}
}

int platform_set_return_value(mcontext_t *mctx, void *value)
{
	mctx->gregs[3] = value;
	return 0;
}

int platform_perform_return(mcontext_t *mctx)
{
	mctx->gregs[32] = mctx->gregs[36]; // ctr reg? :|
	return 0;
}

int platform_continue_execution(mcontext_t *mctx, int idx)
{
	int top, bottom, offset;

	top = (detours[idx].orig >> 8) & 0xffffff;
	bottom = (detours[idx].orig) & 0xff;

	if(top != 0x9421ff) {
		printf("I don't know how to handle detour %d\n", idx);
		crash();
	}

#if 0
0002969c <open>:
   2969c:	94 21 ff 80 	stwu    r1,-128(r1)
--
000610a0 <__mmap>:
   610a0:	94 21 ff c0 	stwu    r1,-64(r1)
--
0008287c <fstat>:
   8287c:	94 21 ff c0 	stwu    r1,-64(r1)
--
000ad680 <close>:
   ad680:	94 21 ff d0 	stwu    r1,-48(r1)
--
000af880 <pread>:
   af880:	94 21 ff c0 	stwu    r1,-64(r1)
--
000afac0 <read>:
   afac0:	94 21 ff e0 	stwu    r1,-32(r1)
#endif

	offset = 256 - bottom;

	mctx->gregs[1] -= offset;
	mctx->gregs[32] += 4;

	return 0;
}

