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

// copied from musl libc in case of address sanitization
#ifndef REG_48
#define REG_R8          0
#define REG_R9          1
#define REG_R10         2
#define REG_R11         3
#define REG_R12         4
#define REG_R13         5
#define REG_R14         6
#define REG_R15         7
#define REG_RDI         8
#define REG_RSI         9
#define REG_RBP         10
#define REG_RBX         11
#define REG_RDX         12
#define REG_RAX         13
#define REG_RCX         14
#define REG_RSP         15
#define REG_RIP         16
#define REG_EFL         17
#define REG_CSGSFS      18
#define REG_ERR         19
#define REG_TRAPNO      20
#define REG_OLDMASK     21
#define REG_CR2         22
#endif

// </copy>


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
