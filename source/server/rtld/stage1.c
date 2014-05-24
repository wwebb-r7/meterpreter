
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <elf.h>
#include <signal.h>
#include <limits.h>

#include "libc.h"
#include "zlib.h"
#include "stage3.h"

#include "libpcap.h"
#include "libcrypto.h"
#include "libssl.h"
#include "libsupport.h"
#include "libmetsrv_main.h"

#include "libc_offsets.h"

#include "crash.h"
#include "elfloader.h"
#include "blob.h"
#include "platform.h"

void reset_signal_handlers();
void cleanup_fd();
void and_jump(blob_t *stack_blob, blob_t *libc_blob);
int setup_stack(blob_t *stack, blob_t *libc, blob_t *stage3);
int setup_detours(blob_t *libc, blob_t *stage3);
int add_library(blob_t *stage3, char *name, blob_t *library);
void copy_loader_struct(blob_t *stage3, loader_t *loader);

#define STACK_SIZE (1024 * 1024)
// #define LOADER_SIZE ((1024 * 1024) * 8) // for 32 bits.
#define LOADER_SIZE ((1024 * 1024) * 64) // for 64 bits ..

int main(int argc, char **argv)
{
	loader_t loader;
	blob_t libc_blob;
	blob_t stage3_blob;
	blob_t stack_blob;
	blob_t libpcap_blob;
	blob_t libcrypto_blob;
	blob_t libssl_blob;
	blob_t libsupport_blob;
	blob_t libmetsrv_main_blob;

	blob_t loaded_libc_blob;
	blob_t loaded_stage3_blob;
	blob_t loaded_libpcap_blob;
	blob_t loaded_libcrypto_blob;
	blob_t loaded_libssl_blob;
	blob_t loaded_libsupport_blob;
	blob_t loaded_libmetsrv_main_blob;
	/*
	 * At this point, we're executing on an unknown stack, with an unknown
	 * stack size, so let's try to keep things as a minimum
	 *
	 * XXX - it might be worth while having a "minstack" .data section
	 * stack variable, and moving our stack pointer to that. Investigate
	 * later.
	 */
	reset_signal_handlers();
	cleanup_fd();

	if(loader_alloc(&loader, STACK_SIZE + LOADER_SIZE) != 0) {
		printf("loader_alloc failed!\n"); fflush(stdout);
		crash();
	}

	// stack_blob points to the /bottom/ of the memory allocation. Will be fixed
	// up later on when we deal with preparing the stack for libc entry point.
	//
	memset(&stack_blob, 0, sizeof(blob_t));
	stack_blob.blob = loader.base;
	stack_blob.length = STACK_SIZE;

	loader.next += STACK_SIZE;

	// set up stack allocation.

	printf("loading libc.so\n"); fflush(stdout);
	load_blob((unsigned char *)&libc_start, (int) &libc_size, libc_raw, &libc_blob);
	load_elf_blob(&loader, &libc_blob, &loaded_libc_blob);
	free_blob(&libc_blob);

	printf("loading stage3\n"); fflush(stdout);
	load_blob((unsigned char *)&stage3_start, (int) &stage3_size, stage3_raw, &stage3_blob);
	load_elf_blob(&loader, &stage3_blob, &loaded_stage3_blob);
	free_blob(&stage3_blob);

	printf("loading libpcap\n"); fflush(stdout);
	load_blob((unsigned char *)&libpcap_start, (int) &libpcap_size, libpcap_raw, &libpcap_blob);
	load_elf_blob(&loader, &libpcap_blob, &loaded_libpcap_blob);
	free_blob(&libpcap_blob);

	printf("loading libcrypto\n"); fflush(stdout);
	load_blob((unsigned char *)&libcrypto_start, (int) &libcrypto_size, libcrypto_raw, &libcrypto_blob);
	load_elf_blob(&loader, &libcrypto_blob, &loaded_libcrypto_blob);
	free_blob(&libcrypto_blob);

	printf("loading libssl\n"); fflush(stdout);
	load_blob((unsigned char *)&libssl_start, (int) &libssl_size, libssl_raw, &libssl_blob);
	load_elf_blob(&loader, &libssl_blob, &loaded_libssl_blob);
	free_blob(&libssl_blob);

	printf("loading libsupport\n"); fflush(stdout);
	load_blob((unsigned char *)&libsupport_start, (int)&libsupport_size, libsupport_raw, &libsupport_blob);
	load_elf_blob(&loader, &libsupport_blob, &loaded_libsupport_blob);
	free_blob(&libsupport_blob);

	printf("loading libmetsrv_main\n"); fflush(stdout);
	load_blob((unsigned char *)&libmetsrv_main_start, (int)&libmetsrv_main_size, libmetsrv_main_raw, &libmetsrv_main_blob);
	load_elf_blob(&loader, &libmetsrv_main_blob, &loaded_libmetsrv_main_blob);
	free_blob(&libmetsrv_main_blob);
	printf("finished loading libraries\n");

	setup_stack(&stack_blob, &loaded_libc_blob, &loaded_stage3_blob); 
	setup_detours(&loaded_libc_blob, &loaded_stage3_blob);

	add_library(&loaded_stage3_blob, "/nx/libpcap.so", &loaded_libpcap_blob);
	add_library(&loaded_stage3_blob, "/nx/libcrypto.so.1.0.0", &loaded_libcrypto_blob);
	add_library(&loaded_stage3_blob, "/nx/libssl.so.1.0.0", &loaded_libssl_blob);
	add_library(&loaded_stage3_blob, "/nx/libsupport.so", &loaded_libsupport_blob);
	add_library(&loaded_stage3_blob, "/nx/libmetsrv_main.so", &loaded_libmetsrv_main_blob);
	copy_loader_struct(&loaded_stage3_blob, &loader);
	printf("--> ENTERING POINT OF NO RETURN <--\n");


	and_jump(&stack_blob, &loaded_libc_blob);

	return 0;
}

// must be in sync with stage3.c ..
struct libraries {
	char name[64];
	void *first_mmap;
	void *second_mmap;
};

void copy_loader_struct(blob_t *stage3, loader_t *loader)
{
	unsigned char *p;

	p = stage3->blob + stage3_loader_info_offset;

	memcpy(p, (void *)loader, sizeof(loader_t));
}

int add_library(blob_t *stage3, char *name, blob_t *library)
{
	static struct libraries *library_ptr;

	if(library_ptr == NULL) {
		library_ptr = (struct libraries *)(stage3->blob + stage3_libraries_offset);
	}

	if(strlen(name) > 63) crash();
	strcpy(library_ptr->name, name);
	library_ptr->first_mmap = library->blob;
	
	library_ptr++;

	return 0;
}


int setup_detours(blob_t *libc, blob_t *stage3)
{
	struct sigaction sa;
	unsigned long *fp;
	unsigned long *detours;

	memset(&sa, 0, sizeof(struct sigaction));

	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = (void *)(stage3->blob + stage3_trap_handler_offset);
	sigaction(PLATFORM_TRAP_SIGNAL, &sa, NULL);

	detours = (unsigned long *)(stage3->blob + stage3_detours_offset);

	fp = (unsigned long *)(libc->blob + libc_open_offset);
	*detours++ = (unsigned long)(fp);
	*detours++ = *fp;
	PLATFORM_TRAP(fp);

	fp = (unsigned long *)(libc->blob + libc_close_offset);
	*detours++ = (unsigned long)(fp);
	*detours++ = *fp;
	PLATFORM_TRAP(fp);

	fp = (unsigned long *)(libc->blob + libc_mmap_offset);
	*detours++ = (unsigned long)(fp);
	*detours++ = *fp;
	PLATFORM_TRAP(fp);

	fp = (unsigned long *)(libc->blob + libc_fstat_offset);
	*detours++ = (unsigned long)(fp);
	*detours++ = *fp;
	PLATFORM_TRAP(fp);

	fp = (unsigned long *)(libc->blob + libc_read_offset);
	*detours++ = (unsigned long)(fp);
	*detours++ = *fp;
	PLATFORM_TRAP(fp);

	fp = (unsigned long *)(libc->blob + libc_pread_offset);
	*detours++ = (unsigned long )(fp);
	*detours++ = *fp;
	PLATFORM_TRAP(fp);

	printf("detours setup\n");
	return 0;
}

// The below should be moved to the platform file at some
// stage.

void and_jump(blob_t *stack_blob, blob_t *libc_blob)
{
	// Where does Napolean keep his armies? In his sleevies.
	Ehdr *ehdr;
	ehdr = (Ehdr *)(libc_blob->blob);

#ifdef __mips__
	register int (*entry)() asm("t9");
	register int *(*sp) asm("sp");

	ehdr = (Ehdr *)(libc_blob->blob);
	entry = (int)(libc_blob->blob + ehdr->e_entry);
	sp = (int *) stack_blob->blob;

	entry();
#elif __arm__
	register int (*entry)() asm("r0");
	register int *(*sp) asm("sp");

	entry = (int)(libc_blob->blob + ehdr->e_entry);
	sp = (int *) stack_blob->blob;

	entry();
#elif __powerpc__
	register int (*entry)() asm("r0");
	register int *(*sp)() asm("sp");

	entry = (int)(libc_blob->blob + ehdr->e_entry);
	sp = (int *) stack_blob->blob;

	entry();
#elif __x86_64__
	// this code isn't -fomit-frame-pointer friendly ..

	register long (*entry)() asm ("rax");
	register long *(*sp) asm("rsp");

	sp = (long *) stack_blob->blob;
	entry = (long)(libc_blob->blob + ehdr->e_entry);

	// calling will mess up our stack ..
	asm("jmpq *%rax;");
#elif __i386__
	register long (*entry)() asm ("eax");
	register long *(*sp) asm("esp");

	sp = (long *) stack_blob->blob;
	entry = (long)(libc_blob->blob + ehdr->e_entry);

	// calling will mess up our stack ..
	asm("jmp *%eax;");
#endif

	printf("hmmm. And libc returned back to us :/\n"); fflush(stdout);
	crash();
}

int setup_stack(blob_t *stack, blob_t *libc, blob_t *stage3) 
{
	unsigned long *ptr, *argv, *envp, *tmp;
	unsigned char *p;
	Ehdr *ehdr;
	Phdr *phdr;

	printf("--> setup_stack %p, %p, %p\n", stack, libc, stage3); fflush(stdout);
	printf("--> libc->blob = %p\n", libc->blob);
	printf("--> stage3->blob = %p\n", stage3->blob);

	ehdr = (Ehdr *)(stage3->blob);
	phdr = (Phdr *)(stage3->blob + ehdr->e_phoff);

	stack->blob += (STACK_SIZE - 4096);
	ptr = (unsigned long *)(stack->blob);

	// *ptr++ = 0; // return address
	*ptr++ = 1; // argc
	argv = ptr;
	ptr++;
	*ptr++ = 0; // null terminate
	envp = ptr;
	ptr ++;
	*ptr++ = 0;

#define set_auxv(key, value) do { *ptr++ = (unsigned long)(key); *ptr++ = (unsigned long)(value); } while(0)
	set_auxv(AT_UID, 0);
	set_auxv(AT_EUID, 0);
	set_auxv(AT_GID, 0);
	set_auxv(AT_EGID, 0);
	set_auxv(AT_SECURE, 0);
	set_auxv(AT_PAGESZ, getpagesize());
	set_auxv(AT_BASE, libc->blob);

	// set up elf structures ..
	set_auxv(AT_PHDR, phdr);
	set_auxv(AT_PHNUM, ehdr->e_phnum);
	set_auxv(AT_PHENT, ehdr->e_phentsize);
	tmp = ptr;
	set_auxv(AT_RANDOM, tmp + 6);
	set_auxv(AT_ENTRY, stage3->blob + ehdr->e_entry);
	set_auxv(AT_NULL, 0);

	// set up "random" values
	set_auxv(0xabad1dea, 0xdefac8ed);
	set_auxv(0xcafed00d, 0xc0ffee);
	set_auxv(0, 0);

#undef set_auxv

	p = (unsigned char *)(ptr);
	*argv = (unsigned long)(ptr);
	strcpy((char *)p, "argv0");
	p += 6;
	*envp = (unsigned long)(p);
	strcpy((char *)p, "LD_LIBRARY_PATH=/nx");
	p += 6;

	return 0;
}

void reset_signal_handlers()
{
//	int i;
//	for(i = 0; i < 128; i++) signal(i, 0);
}

void cleanup_fd()
{
	// XXX, to do.
}


