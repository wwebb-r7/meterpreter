#ifndef PLATFORM_H
#define PLATFORM_H

#include <sys/types.h>
#include <signal.h>

struct detours {
	unsigned long addr;
	unsigned long orig;
};
#define HOOKED_FUNC_COUNT 6

extern struct detours detours[HOOKED_FUNC_COUNT];

// PLATFORM_PC_REG = register that contains PC reg
// PLATFORM_OFFSET = offset to the PC register to the instruction that caused the fault.
//   Probably really only useful on x86, to be honest.

#ifdef __mips__
// MIPS big endian
#define PLATFORM_PC_REG(x) (x->pc)

#define PLATFORM_TRAP(ptr) \
	do { \
		(*ptr) = 0x0000000d; \
	} while(0)


#endif // __mips__

#ifdef  __arm__
// ARM .. need to check endian
#define PLATFORM_PC_REG(x) (x->arm_pc)

#define PLATFORM_TRAP(ptr) \
	do { \
		/* instruct 0xe7f001f0 causes a SIGTRAP */ \
		(*ptr) = 0xe7f001f0; \
	} while(0)

#endif // __arm__

#ifdef __powerpc__

#define PLATFORM_PC_REG(x) (x->gregs[32])

#define PLATFORM_TRAP(ptr) \
	do { \
		(*ptr) = 0x7fe00008; \
	} while(0)

#endif // __powerpc__

#ifdef __x86_64__

#define PLATFORM_PC_REG(x) (x->gregs[REG_RIP])
#define PLATFORM_OFFSET(x) (x - 1)

#define PLATFORM_TRAP(ptr) \
	do { \
		(*ptr) = (((*ptr) & (~0xff)) | 0xcc); \
	} while(0)

#endif

#ifdef __i386__

#define PLATFORM_PC_REG(x) (x->gregs[REG_EIP])
#define PLATFORM_OFFSET(x) (x - 1)

#define PLATFORM_TRAP(ptr) \
        do { \
                (*ptr) = (((*ptr) & (~0xff)) | 0xcc); \
        } while(0)

#endif


#ifndef PLATFORM_OFFSET
#define PLATFORM_OFFSET(x) (x)
#endif

#ifndef PLATFORM_TRAP_SIGNAL
#define PLATFORM_TRAP_SIGNAL (SIGTRAP)
#endif

void *platform_arg(mcontext_t *mctx, int param);
int platform_set_return_value(mcontext_t *mctx, void *value);
int platform_perform_return(mcontext_t *mctx);
int platform_continue_execution(mcontext_t *mctx, int idx);

#endif
