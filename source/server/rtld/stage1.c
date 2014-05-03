
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>

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


inline int loader_alloc(loader_t *loader, size_t sz);

#define STACK_SIZE (1024 * 1024)
#define PADDING (3 * 4096) // spare pages for PROT_NONE, etc.

#define crash() do { *((unsigned char *)NULL) = 0; } while(0)

int main(int argc, char **argv)
{
	loader_t loader;
	blob_t libc_blob;
	blob_t stage3_blob;
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
		printf("loader_alloc failed!\n");
		exit(EXIT_FAILURE);
	}

	// set up stack allocation.

	printf("blob() .. %08x, %08x, %08x\n", &libc_start, &libc_size, libc_raw); fflush(stdout);
	load_blob((unsigned char *)&libc_start, (int) &libc_size, libc_raw, &libc_blob);
	load_blob((unsigned char *)&stage3_start, (int) &stage3_size, stage3_raw, &stage3_blob);

	return 0;
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
	// Add in a prev pointer to struct zliballoc, and have it so that
	// we can free() at most 1 allocation, see if it saves memory
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

