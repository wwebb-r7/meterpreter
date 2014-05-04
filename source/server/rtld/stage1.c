
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <elf.h>

#include "libc.h"
#include "zlib.h"
#include "stage3.h"

typedef struct loader {
	unsigned char *base;
	size_t length;
	unsigned char *next;
} loader_t;

typedef struct blob {
	unsigned char *blob;
	size_t length;
	size_t alloc_size;
} blob_t;

void reset_signal_handlers();
void cleanup_fd();
int load_blob(unsigned char *start, unsigned int size, unsigned int raw_size, blob_t *blob);
int load_elf_blob(loader_t *loader, blob_t *blob_in, blob_t *blob_out);
void free_blob(blob_t *blob);

inline int loader_alloc(loader_t *loader, size_t sz);

#define STACK_SIZE (1024 * 1024)
#define PADDING (3 * 4096) // spare pages for PROT_NONE, etc.

#define crash() do { *((unsigned char *)NULL) = 0; } while(0)

int main(int argc, char **argv)
{
	loader_t loader;
	blob_t libc_blob;
	blob_t stage3_blob;
	blob_t stack_blob;

	blob_t loaded_libc_blob;
	blob_t loaded_stage3_blob;

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

	if(loader_alloc(&loader, libc_raw + stage3_raw + STACK_SIZE + PADDING) != 0) {
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

	printf("blob() .. %08x, %08x, %08x\n", &libc_start, &libc_size, libc_raw); fflush(stdout);
	load_blob((unsigned char *)&libc_start, (int) &libc_size, libc_raw, &libc_blob);
	load_elf_blob(&loader, &libc_blob, &loaded_libc_blob);
	free_blob(&libc_blob);

	load_blob((unsigned char *)&stage3_start, (int) &stage3_size, stage3_raw, &stage3_blob);
	load_elf_blob(&loader, &stage3_blob, &loaded_stage3_blob);
	free_blob(&stage3_blob);

	setup_stack(&stack_blob, &loaded_libc_blob, &stage3_blob);

	return 0;
}

int setup_stack(blob_t *stack, blob_t *libc, blob_t *stage3)
{
	unsigned int *ptr;
	Elf32_Ehdr *ehdr;
	Elf32_Phdr *phdr;

	ehdr = (Elf32_Ehdr *)(stage3->blob;
	phdr = (Elf32_Phdr *)(stage3->blob + ehdr->e_phoff);

	stack->blob += (STACK_SIZE - 2048);
	ptr = (unsigned int *)(stack->blob);

	*ptr++ = 0; // return address
	*ptr++ = 1; // argc
	*ptr++ = NULL; // argv[0]
	*ptr++ = NULL; // argv[1]
	*ptr++ = NULL; // envp

#define set_auxv(key, value) do { *ptr++ = key; *ptr++ = value; } while(0)
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
	set_auxv(AT_PHENT, ehdr->e_phent_size);
	set_auxv(AT_RANDOM, ptr + 3);
	set_auxv(AT_NULL, 0);
	// set up "random" values
	set_auxv(0xabad1dea, 0xdefac8ed);
	set_auxv(0xcafed00d, 0xc0ffee);

#undef set_auxv



}

/*
 * The loader_alloc is effectively the same as the zliballoc, except I want to
 * make the loader_alloc PaX / SeLinux memprot aware, and do a dual mapping
 * in case that is a problem.
 */

int loader_alloc(loader_t *loader, size_t sz)
{
	memset(loader, 0, sizeof(loader_t));

	loader->length = sz;
	loader->next = loader->base = mmap(NULL, sz, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	if(loader->base == MAP_FAILED) {
		return -1;
	}

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

/*
 * Keep state from the "allocator" here, passed around the z_stream opaque
 */

struct zliballoc {
	unsigned char *base;
	size_t len;
	unsigned char *next;
	unsigned char *prev;
};

#define MIN_HINT_SIZE (((32 * 2) + (32 / 2)) * 1024)

// Initialize the zliballoc structure
int init_zliballoc(struct zliballoc *za, size_t hint)
{
	size_t requested;
	memset(za, 0, sizeof(struct zliballoc));

	if(hint < MIN_HINT_SIZE) {
		// inflate requires a minimum of 32k for windowBits=15 plus
		// a few kilobytes for small objects. since we don't free
		// any allocations, let's 2.5 the size of that for lee way.
		requested = MIN_HINT_SIZE;
	} else {
		requested = (hint + 4095) & ~4095;
	}

	printf("init_zlib(), requesting %d bytes\n", requested); fflush(stdout);

	za->base = za->next = mmap(NULL, requested, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	if(za->base == (MAP_FAILED)) {
		printf("init_zliballoc(): mmap failed, gave us %s\n", strerror(errno)); fflush(stdout);
		return -1;
	}
	za->len = requested;

	return 0;
}

void free_zliballoc(struct zliballoc *za)
{
	if(munmap(za->base, za->len) == -1) {
		printf("free_zliballoc(): munmap gave us %s\n", strerror(errno)); fflush(stdout);
	}
	memset(za, 0xcc, sizeof(struct zliballoc));
}

void *zalloc(void *opaque, unsigned int count, unsigned int size)
{
	struct zliballoc *za = opaque;
	size_t wanted;
	unsigned char *nextnext, *ret;

	// int wrap below.
	wanted = ((count * size) + 15) & ~15;

	// printf("zalloc .. opaque is %p .. requesting %d bytes\n", opaque, wanted);

	za->prev = za->next;

	nextnext = za->next + wanted;
	if(nextnext >= (za->base + za->len)) {
		// Please Sir, I want some more.
		//
		// If needed, we can mremap() the memory with MREMAP_FIXED
		// in order to ask for more memory at the same address.
		// However, I'll add that in if needed. 

		printf("requested a %d bytes, only %d bytes remaining\n", wanted, (int)(za->next) - (int)(za->base));
		fflush(stdout);
		crash();

		return NULL;
	}

	ret = za->next;
	za->next = nextnext;

	return ret;
}

void zfree(void *opaque, void *addr)
{
	struct zliballoc *za = opaque;

	// printf("zfree .. opaque is %p\n", opaque);
	if(za->prev == addr && addr != NULL) {
#if 0
		size_t saved;
		saved = (int)(za->next)- (int)(za->prev);
		printf("[BONUS] can free an allocation, saved %d bytes\n", saved);
#endif

		// On libc.o, this reclaimed about ~40k in total, in an otherwise
		// empty stage3.o, it saved 538 bytes or so. At a cost of 4 bytes,
		// it's worth it :)

		za->next = za->prev;
		za->prev = NULL;
	}
}

// XXX, investigate if we can decompress directly into the loader, via
// controlling the avail_out buffer size and reading in headers etc.
// Saves copying memory around, memory allocations.

int load_blob(unsigned char *start, unsigned int size, unsigned int raw_size, blob_t *blob)
{
	z_stream stream;
	struct zliballoc za;
	int status;

	printf("in blob\n"); fflush(stdout);
	// raw_size += 0;

	memset(&stream, 0, sizeof(z_stream));
	memset(blob, 0, sizeof(blob_t));

	// raw_size/8 gives about ~14k spare for libc.o loading.
	init_zliballoc(&za, raw_size/8);

	blob->alloc_size = (raw_size + 4095) & ~4095;
	blob->blob = mmap(0, blob->alloc_size, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	blob->length = raw_size;

	if(blob->blob == MAP_FAILED) {
		printf("allocating blob failed ..\n");
		crash();
	}

	stream.opaque = &za;
	stream.zalloc = zalloc;
	stream.zfree = zfree;
	stream.avail_in = size;
	stream.next_in = start;
	stream.avail_out = blob->alloc_size;
	stream.next_out = blob->blob;

	printf("inflating ..\n"); fflush(stdout);
	if(inflateInit2(&stream, -MAX_WBITS) != Z_OK) {
		// aw, crap!
		printf("give me a break man, inflateInit2 failed!\n"); fflush(stdout);
		crash();
	}

	status = inflate(&stream, Z_FINISH);

#if 1
	{
		int diff;

		diff = (int)(za.next) - (int) (za.base);
		printf("allocated %d bytes, used %d, remainder = %d\n", za.len, diff, za.len - diff); 
		printf("output_size is %d\n", blob->alloc_size);
	}
#endif

	if(status != Z_STREAM_END) {
		printf("decompression failed, status is %d, error is %s\n", status, stream.msg);
		printf("avail_out is %d\n", stream.avail_out);
		fflush(stdout);
		crash();
	}

	free_zliballoc(&za);

	return 0;
}

// 32 bit only for now, will do 64 bit once 32 bit platforms have been done
// I think.

int load_elf_blob(loader_t *loader, blob_t *blob_in, blob_t *blob_out)
{
	Elf32_Ehdr *ehdr;
	Elf32_Phdr *phdr;
	int i;
	size_t filesz, memsz, offsz;

	ehdr = (Elf32_Ehdr *)blob_in->blob;
	phdr = (Elf32_Phdr *)(blob_in->blob + ehdr->e_phoff);

	if((int)(loader->next) & 4095) crash();

	/*
	 * Sanity checking?
	 *   Especially make sure all modules have same OS/platform/endian?
	 *   That might be a Makefile time thing, perhaps
	 */

	memset(blob_out, 0, sizeof(blob_t));
	blob_out->blob = loader->next;

	printf("ehdr is at %p, and phdr is at %p\n", ehdr, phdr);
	for(i = 0; i < ehdr->e_phnum; i++, phdr++) {
		if(phdr->p_type != PT_LOAD) continue;

		printf("Found a PT_LOAD segment at %d\n", i);

		offsz = phdr->p_vaddr & ~4095;
		filesz = phdr->p_filesz + (phdr->p_vaddr & 4095);
		memsz = ((phdr->p_memsz + (phdr->p_vaddr & 4095)) + 4095) & ~4095;

		memcpy(blob_out->blob + offsz, blob_in->blob + (phdr->p_offset & ~4095), filesz);

		loader->next += memsz;
		blob_out->length += memsz;
	}

	return 0;
}

void free_blob(blob_t *blob)
{
	if(blob->length) {
		munmap(blob->blob, blob->alloc_size);
	}
	memset(blob, 0, sizeof(blob_t));
}
