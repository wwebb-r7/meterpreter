#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>

#define _GNU_SOURCE
#include <signal.h>

#define crash() do { (*(unsigned char *)NULL) = 0xff; } while (0)

//
// open()    syscall()
// close()   __syscall_cp()
// mmap()    syscall()
// fstat64() __syscall()
//
// Instead of function redirecting, is there a better way to do this?
// 

#define HOOKED_FUNC_COUNT 6
#define PLATFORM_OFFSET(x) (x)

// pcap, crypto, ssl, support, metsrv, custom
#define LIBRARY_COUNT 7


#define OPEN_OFFSET  0
#define CLOSE_OFFSET 1
#define MMAP_OFFSET  2
#define FSTAT_OFFSET 3
#define READ_OFFSET 4
#define PREAD_OFFSET 5

struct detours { 
	unsigned long addr;
	unsigned long orig;
};

// must be in sync with stage1.c ..
struct libraries {
	char name[32];
	void *first_mmap;
	void *second_mmap;
};


struct detours detours[HOOKED_FUNC_COUNT];
struct libraries libraries[LIBRARY_COUNT];

static int fd_to_library_id(int fd)
{
	int match, id;
	
	id = (fd & 0xff);
	match = (fd >> 8) & 0xffffff;
	
	if(match != 31337) return -1;
	if(id < 0 || id >= LIBRARY_COUNT) return -1;
	
	return id;
}

void *my_open(int *emul, char *name, int flags, mode_t mode)
{
	int i;
	int ret;

	printf("my_open(\"%s\", %d, %o)\n", name, flags, mode); fflush(stdout);

	for(i = 0; i < LIBRARY_COUNT; i++) {
		printf("%s vs %s\n", libraries[i].name, name);
		if(strcmp(libraries[i].name, name) == 0) {
			printf("my_open(): found %s at %d\n", name, i);
			break;
		}
	}

	if(i == LIBRARY_COUNT) {
		// not found.
		return NULL;
	}

	if(flags != (O_RDONLY|O_CLOEXEC)) {
		printf("my_open(): hmm. flags are %d, not %d .. \n", flags, (O_RDONLY|O_CLOEXEC));
		fflush(stdout);
		crash();
		return NULL;
	}

	*emul = 1;
	ret = (31337 << 8) | i;

	return (void *)(ret);
}

void *my_close(int *emul, int fd)
{
	int id;

	id = fd_to_library_id(fd);
	if(fd == -1) return NULL;

	*emul = 1;	
	return NULL;
}

void *my_fstat(int *emul, int fd, struct stat *statbuf)
{
	int id;

	printf("my_fstat(.., 0x%08x) -> fd is %d, id is %d\n", statbuf, fd, id);
	fflush(stdout);

	id = fd_to_library_id(fd);
	if(id == -1) return NULL;
	
	printf("emulating fstat()\n");

	*emul = 1;
	memset(statbuf, 0, sizeof(struct stat));
	statbuf->st_dev = 0x31337;
	statbuf->st_ino = id;
	
	return NULL;

}

void *my_read(int *emul, int fd, void *buffer, size_t count)
{
	int id;

	printf("my_read(%d, 0x%08x, %d) .. \n", fd, buffer, count);

	id = fd_to_library_id(fd);
	if(id == -1) return NULL;
	
	printf("emulating read.. first_mmap is at 0x%08x\n", libraries[id].first_mmap); 
	fflush(stdout);

	*emul = 1;
	// XXX, does not implement a fd offset pointer thing.
	memcpy(buffer, libraries[id].first_mmap, count);

	return (void *)count;
}

void *my_pread(int *emul, int fd, void *buffer, size_t count, off_t offset)
{
	int id;
	
	printf("my_pread(%d, 0x%08x, %d, %d) .. \n", fd, buffer, count, offset);

	id = fd_to_library_id(fd);
	if(id == -1) return NULL;
	
	printf("emulating pread() .. \n"); fflush(stdout);

	*emul = 1;
	memcpy(buffer, libraries[id].first_mmap + offset, count);
	
	return (void *)count;
}

void *my_mmap(int *emul, void *addr, size_t length, int prot, int flags, int fd, off_t off)
{
	int id;

	printf("my_mmap(%p, %d, %d, %d, %d, %p)\n", 
		addr,
		length,
		prot,
		flags,
		fd, 
		off
	); fflush(stdout);

	id = fd_to_library_id(fd);
	if(id == -1) return NULL;

	printf("emulating %s mmap()..\n", addr ? "second" : "first"); fflush(stdout);
	*emul = 1;

	if(!addr) {
		// first mmap
		return libraries[id].first_mmap;
	} else {
		// second mmap of data
		return addr;
	}
}

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
	crash();
	return 0;
}

void trap_handler(int sig, siginfo_t *info, void *_ctx)
{
	int i;
	unsigned long *stack;
	ucontext_t *ctx = (ucontext_t *)_ctx;
	mcontext_t *mctx = &ctx->uc_mcontext;
	int emulated;
	void *ret;
	
	ret = NULL;
	emulated = 0;

#if 1
	printf("PC is %08x\n", mctx->pc);
	for(i = 0; i < 32; i++) {
		printf("reg[%d] is %016llx, fpreg[%d] is %016llx\n", i, mctx->regs[i], i, mctx->fpregs[i]);
	}

	stack = mctx->regs[30];
	for(stack = mctx->regs[30], i = 0; i < 32; i++) {
		printf("stack[%d] is 0x%08x\n", i, stack[i]);
	} 

#endif

	for(i = 0; i < HOOKED_FUNC_COUNT; i++) {
		if(detours[i].addr == PLATFORM_OFFSET(mctx->pc)) {
			printf("--> found offset at %d! <--\n", i);
			break;
		}
	}

	fflush(stdout);

	switch(i) {
		case OPEN_OFFSET:
			ret = my_open(&emulated, 
				(char *)platform_arg(mctx, 0), 
				(int)platform_arg(mctx, 1), 
				(mode_t)platform_arg(mctx, 2)
			);
			break;
		case CLOSE_OFFSET:
			ret = my_close(&emulated, (int)platform_arg(mctx, 0));
			break;
		case FSTAT_OFFSET:
			ret = my_fstat(&emulated, 
				(int)platform_arg(mctx, 0), 
				(struct stat *)platform_arg(mctx, 1)
			);
			break;
		case MMAP_OFFSET:
			ret = my_mmap(&emulated,
				platform_arg(mctx, 0), // addr
				(size_t ) platform_arg(mctx, 1), // length
				(int) platform_arg(mctx, 2), // prot
				(int) platform_arg(mctx, 3), // flags
				(int) platform_arg(mctx, 4), // fd
				(off_t) platform_arg(mctx, 5) // offset
			);

			break;
		case READ_OFFSET:
			ret = my_read(&emulated, 
				(int)platform_arg(mctx, 0), // fd
				platform_arg(mctx, 1), // buffer
				(size_t) platform_arg(mctx, 2) // size
			);
			break;
		case PREAD_OFFSET:
			ret = my_pread(&emulated, 
				(int)platform_arg(mctx, 0), 
				platform_arg(mctx, 1),
				(size_t) platform_arg(mctx, 2),
				(off_t) platform_arg(mctx, 3)
			);
			break;
		case HOOKED_FUNC_COUNT:
			// oh, snap!
			printf("Unable to find where the SIGTRAP came from, sorry :(\n");
			crash();
	}

	if(emulated) {
		printf("Emulating and returning\n"); fflush(stdout);
		platform_set_return_value(mctx, ret);
		platform_perform_return(mctx);
		return;
	}

	printf("Continuing execution\n"); fflush(stdout);
	// otherwise, we need to continue execution .. 
	platform_continue_execution(mctx, i);
	
}

int main(int argc, char **argv)
{
	void *x;
	void *y;
	printf("dlopen start\n");
	x = dlopen("libpcap.so", RTLD_NOW);
	if(! x) {
		printf("Failed to dlopen(), dlerror is %s\n", dlerror());
	}
	printf("dlopen finish .. %08x\n", x);

	y = dlsym(x, "sassy_syscall");
	printf("it's at 0x%08x\n", y);

	return 0;
}
