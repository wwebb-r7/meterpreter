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
#include <sys/socket.h>

#define _GNU_SOURCE
#include <signal.h>

#include "elfloader.h"
#include "blob.h"
#include "platform.h"
#include "crash.h"

//
// open()    syscall()
// close()   __syscall_cp()
// mmap()    syscall()
// fstat64() __syscall()
//
// Instead of function redirecting, is there a better way to do this?
//

// pcap, crypto, ssl, support, metsrv, custom
#define LIBRARY_COUNT 12

#define OPEN_OFFSET  0
#define CLOSE_OFFSET 1
#define MMAP_OFFSET  2
#define FSTAT_OFFSET 3
#define READ_OFFSET 4
#define PREAD_OFFSET 5

char *library_calls[] = {
	"open", "close", "mmap",
	"fstat", "read", "pread",
	NULL
};

// must be in sync with stage1.c ..
struct libraries {
	char name[64];
	void *first_mmap;
	void *second_mmap;
};

// this comes pre-populated due to stage1
// code populating this structure for us.
loader_t loader_info;

struct detours detours[HOOKED_FUNC_COUNT];
struct libraries libraries[LIBRARY_COUNT];

static int in_dlopen;

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

	printf("my_open(\"%s\", %d, %o)\n", name, flags, mode);
	fflush(stdout);

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

	if(memcmp(libraries[id].first_mmap, "\x7f\x45\x4c\x46", 4) != 0) {
		char *p;
		p = (unsigned char *)(libraries[id].first_mmap);

		printf("%s is not an elf file, yet emulating a read for it?\n", libraries[id].name);
		printf("first four bytes are %02x%02x%02x%02x\n",
			p[0],
			p[1],
			p[2],
			p[3]
		);
		crash();
	}

	// XXX, does not implement a fd offset pointer thing.
	// shouldn't matter, however.

	*emul = 1;
	memcpy(buffer, libraries[id].first_mmap, count);

	return (void *)count;
}

void *my_pread(int *emul, int fd, void *buffer, size_t count, off_t offset)
{
	int id;

	printf("my_pread(%d, 0x%08x, %d, %d) .. \n", fd, buffer, count, offset);

	id = fd_to_library_id(fd);
	if(id == -1) return NULL;

	printf("emulating pread() .. \n");

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
	);

	id = fd_to_library_id(fd);

	if(id == -1) {
		printf("in_dlopen is set to %d .. addr is %p\n", in_dlopen, addr);
		if(in_dlopen && addr) {
			unsigned char *x;
			size_t cnt;

			printf("dlopen wants to zerofill some memory. checking it's all 0\n");

			*emul = 1;
			x = (unsigned char *)addr;
			for(cnt = 0; cnt < length; cnt++) {
				if(x[cnt] != 0) {
					printf("offset %d has byte %02x\n", cnt, x[cnt]);
					printf("actually it's %s if that helps :/\n", x + cnt);
					crash();
				}
			}
			printf("nup, all good. clear to go!\n");
			return addr;
		}

		return NULL;
	}



	printf("emulating %s mmap()..\n", addr ? "second" : "first");
	*emul = 1;

	if(!addr) {
		// first mmap
		return libraries[id].first_mmap;
	} else {
		// second mmap of data
		return addr;
	}
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
#ifdef __mips__
	printf("PC is %08x\n", mctx->pc);
	for(i = 0; i < 32; i++) {
		printf("reg[%d] is %016llx, fpreg[%d] is %016llx\n", i, mctx->regs[i], i, mctx->fpregs[i]);
	}

	stack = mctx->regs[30];
	for(stack = mctx->regs[30], i = 0; i < 32; i++) {
		printf("stack[%d] is 0x%08x\n", i, stack[i]);
	}

#endif
#ifdef __arm__
        // unsigned long trap_no, error_code, oldmask;
        // unsigned long arm_r0, arm_r1, arm_r2, arm_r3;
        // unsigned long arm_r4, arm_r5, arm_r6, arm_r7;
        // unsigned long arm_r8, arm_r9, arm_r10, arm_fp;
        // unsigned long arm_ip, arm_sp, arm_lr, arm_pc;
        // unsigned long arm_cpsr, fault_address;
	printf("trap_no: %08x, error_code: %08x, oldmask: %08x\n", mctx->trap_no, mctx->error_code, mctx->oldmask);
	printf("r0: %08x, r1: %08x, r2: %08x, r3: %08x\n", mctx->arm_r0, mctx->arm_r1, mctx->arm_r2, mctx->arm_r3);
	printf("r4: %08x, r5: %08x, r6: %08x, r7: %08x\n", mctx->arm_r4, mctx->arm_r5, mctx->arm_r6, mctx->arm_r7);
	printf("r8: %08x, r9: %08x, 10: %08x, fp: %08x\n", mctx->arm_r8, mctx->arm_r9, mctx->arm_r10, mctx->arm_fp);
	printf("ip: %08x, sp: %08x, lr: %08x, pc: %08x\n", mctx->arm_ip, mctx->arm_sp, mctx->arm_lr, mctx->arm_pc);
	printf("cpsr: %08x, fault: %08x\n", mctx->arm_cpsr, mctx->fault_address);
#endif
#ifdef __powerpc__
	// typedef unsigned long greg_t, gregset_t[48];
	for(i = 0; i < (sizeof(mctx->gregs) / sizeof(unsigned long)); i+=4) {
		printf("%02d: 0x%08x, %02d: 0x%08x, %02d: 0x%08x, %02x: 0x%08x\n", 
			i, mctx->gregs[i], i+1, mctx->gregs[i+1], 
			i+2, mctx->gregs[i+2], i+3, mctx->gregs[i+3]
		);	
	}
#endif
#ifdef __x86_64__
	// typedef unsigned long greg_t, gregset_t[48];
	for(i = 0; i < (sizeof(mctx->gregs) / sizeof(unsigned long)); i+=4) {
		printf("%02d: 0x%016llx, %02d: 0x%016llx, %02d: 0x%016llx, %02x: 0x%016llx\n",
			i, mctx->gregs[i], i+1, mctx->gregs[i+1],
			i+2, mctx->gregs[i+2], i+3, mctx->gregs[i+3]
		);
	}
#endif

	printf("First three arguments are as follows\n");
	printf("0x%llx 0x%llx 0x%llx\n",
		platform_arg(mctx, 0),
		platform_arg(mctx, 1),
		platform_arg(mctx, 2)
	);
	fflush(stdout);

#endif

	for(i = 0; i < HOOKED_FUNC_COUNT; i++) {
		if(detours[i].addr == PLATFORM_OFFSET(PLATFORM_PC_REG(mctx))) {
			printf("--> found offset at %d, which is %s! <--\n", i, library_calls[i]);
			break;
		}
	}

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
		printf("Emulating and returning\n");
		platform_set_return_value(mctx, ret);
		platform_perform_return(mctx);
		return;
	}

	printf("Continuing execution\n");
	// otherwise, we need to continue execution ..
	platform_continue_execution(mctx, i);

}

void *load_dependencies()
{
	void *x;

	// libmetsrv_main must be last on the list.
	char *dependencies[] = {
		"libpcap.so", "libcrypto.so.1.0.0",
		"libssl.so.1.0.0", "libsupport.so",
		"libmetsrv_main.so", NULL
	};
	int i;

	in_dlopen = 1;

	for(i = 0; dependencies[i]; i++) {
		printf("performing a dlopen on %s\n", dependencies[i]);

		x = dlopen(dependencies[i], RTLD_LAZY);
		if(! x) {
			printf("Failure to dlopen(\"%s\"): %s\n", dependencies[i], dlerror());
			// exit(EXIT_FAILURE);
			crash();
		}

		printf("%s has been loaded at %p\n", dependencies[i], x);
	}

	in_dlopen = 0;
	return x;
}

#include <sys/mman.h>


/*
 * libsupport requires some bionic libc specific symbols. Implement here.
 * __futex_wait influenced from do_wait in musl-libc.
 *
 * At some stage, we might need to move this into libsupport, or change
 * how they're resolved.
 *
 */

#ifndef FUTEX_WAIT
#define FUTEX_WAIT              0
#endif

#ifndef FUTEX_WAKE
#define FUTEX_WAKE              1
#endif

int __futex_wait(volatile void *ftx, int val, const struct timespec *timeout)
{
	int r;
	printf("__futex_wait(%p, %d, %p) called\n", ftx, val, timeout); fflush(stdout);
	r = -syscall(SYS_futex, ftx, FUTEX_WAIT, val, timeout);
	printf("return value is %d - also %s\n", r, strerror(r));

	if(r == EINTR || r == EINVAL || r == ETIMEDOUT) return r;
	return 0;
}

int __futex_wake(volatile void *ftx, int count)
{
	int r;

	printf("__futuex_wake(%p, %d) called\n", ftx, count); fflush(stdout);
	r = -syscall(SYS_futex, ftx, FUTEX_WAKE, 1, NULL);
	printf("return value is %d - also %s\n", r, strerror(r));

	if(r == EINTR || r == EINVAL || r == ETIMEDOUT) return r;
	return 0;
}

pid_t gettid()
{
	return (pid_t) syscall(SYS_gettid);
}

void *dlopenbuf(char *name, void *data, size_t len)
{
	blob_t blob_in = { 0 }, blob_out = { 0 };
	int i;
	void *r;

	blob_in.blob = data;
	blob_in.length = len;

	if(strlen(name) >= (32 - 4)) {
		printf("Filename is too big!\n");
		return NULL;
	}

	if(load_elf_blob(&loader_info, &blob_in, &blob_out) == -1) {
		printf("load_elf_buf failed\n");
		crash();
	}

	for(i = 0; i < LIBRARY_COUNT; i++) {
		if(! libraries[i].name[0]) break;
	}

	if(i == LIBRARY_COUNT) {
		printf("Unable to find a spare spot for loadable libraries\n");
		return NULL;
	}

	strcpy(libraries[i].name, "/nx/");
	strcpy(libraries[i].name + 4, name);
	libraries[i].first_mmap = blob_out.blob;

	in_dlopen = 1;
	r = dlopen(name, RTLD_LAZY);
	in_dlopen = 0;

	return r;
}

int __atomic_inc(volatile int *x)
{
	int ret;
	static pthread_mutex_t mux = PTHREAD_MUTEX_INITIALIZER;

	/*
	 * Yes, this is incredibly lame, and yes, I'm ashamed.
	 * But in my defense, musl-libc doesn't seem to export
	 * atomic symbols, unlike bionic :(
	 */

	printf("atomic inc called\n");
	pthread_mutex_lock(&mux);
	ret = *x;
	*x = *x + 1;
	pthread_mutex_unlock(&mux);
	printf("atomic inc finished\n");

	return ret;
}

// end bionic support.

#define HOST "10.0.2.3"
#define PORT 4444

int connect_to_handler()
{
	int fd;
	struct sockaddr_in sin;

	memset(&sin, 0, sizeof(struct sockaddr_in));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(HOST);
	sin.sin_port = htons(PORT);

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if(! fd) {
		printf("Unable to socket(): %s\n", strerror(errno));
		exit(0);
	}

	if(connect(fd, (void *)&sin, sizeof(struct sockaddr_in)) == -1) {
		printf("Unable to connect(%s, %d): %s\n", HOST, PORT, strerror(errno));
		exit(0);
	}

	return fd;

}

static void turn_on_debugging()
{
	void *handle;
	void *(*enable_debugging)();
	dlerror(); // clear any outstanding dlerror messages.

	handle = dlopen("libsupport.so", RTLD_LAZY);

	enable_debugging = dlsym(handle, "enable_debugging");
	if(! enable_debugging) {
		printf("Can't find enable_debugging function!\n");
		printf("dlerror() indicates the problem is '%s'\n", dlerror());
		crash();
	}

	enable_debugging();
}

int main(int argc, char **argv, char **envp)
{
	void *x;
	long (*server_setup)(int socket);
	int fd;

	// setvbuf(stdout, NULL, 0, _IONBF);

	printf("--> stage3 activated <--\n"); fflush(stdout);

	x = load_dependencies();

	if(! x) {
		printf("load_dependencies() must return the libmetsrv_main handle!\n");
		crash();
	}

	printf("dependencies loaded!\n");
	fflush(stdout);

	server_setup = dlsym(x, "server_setup");
	if(! server_setup) {
		printf("server_setup not found! :(\n");
		crash();
	}

	printf("server_setup found at 0x%08x\n", server_setup);
	fflush(stdout);

	// xxx, determine FD by inpsecting envp I guess ..

	printf("loader_info.base = %p\n", loader_info.base);
	printf("loader_info.length = %d\n", loader_info.length);
	printf("loader_info.next = %p\n", loader_info.next);
	printf("loader_info remaining space = %d\n",
		loader_info.length - (
			(size_t)loader_info.next -
			(size_t)loader_info.base
		)
	);

	fd = connect_to_handler();
	printf("fd for server connection is %d\n", fd); fflush(stdout);

	turn_on_debugging();

	printf("--> calling server setup <--\n");
	fflush(stdout);

	server_setup(fd);

	printf("server_setup() returned ... :-(\n");
	fflush(stdout);
	crash();

	return 0;
}
