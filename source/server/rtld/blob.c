
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <errno.h>

#include "crash.h"
#include "blob.h"
#include "zlib.h"

/*
 * Keep state from the "allocator" here, passed around the z_stream opaque
 */

struct zliballoc {
	unsigned char *base;
	size_t len;
	unsigned char *next;
	unsigned char *prev;
};

#define MIN_HINT_SIZE (1024 * 1024)

// Initialize the zliballoc structure
static int init_zliballoc(struct zliballoc *za, size_t hint)
{
	size_t requested;
	memset(za, 0, sizeof(struct zliballoc));

	if(hint < MIN_HINT_SIZE) {
		//
		// inflate requires a minimum of 32k for windowBits=15 plus
		// a few kilobytes for small objects.
		//
		// it seems that libssl.so being decompressed hits a
		// pathological case, and must be 32k * 16
		//
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

static void free_zliballoc(struct zliballoc *za)
{
	if(munmap(za->base, za->len) == -1) {
		printf("free_zliballoc(): munmap gave us %s\n", strerror(errno)); fflush(stdout);
	}
	memset(za, 0xcc, sizeof(struct zliballoc));
}

static void *zalloc(void *opaque, unsigned int count, unsigned int size)
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

		printf("requested a %d byte allocation, only %d bytes remaining\n", wanted, za->len - ((int)(za->next) - (int)(za->base)));
		fflush(stdout);
		crash();

		return NULL;
	}

	ret = za->next;
	za->next = nextnext;

	return ret;
}

static void zfree(void *opaque, void *addr)
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

	// printf("in blob\n"); fflush(stdout);
	// raw_size += 0;

	memset(&stream, 0, sizeof(z_stream));
	memset(blob, 0, sizeof(blob_t));

	// raw_size/8 gives about ~14k spare for libc.o loading. Combined with 
	// ability to recover one allocation, it jumps up to ~29k left over.
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

	if(memcmp(blob->blob, "\x7f\x45\x4C\x46", 4) != 0) {
		printf("decompressed a non-elf file?!\n"); fflush(stdout);
		crash();
	}

	free_zliballoc(&za);

	return 0;
}

void free_blob(blob_t *blob)
{
	if(blob->alloc_size) {
		munmap(blob->blob, blob->alloc_size);
	}
	memset(blob, 0xcd, sizeof(blob_t));
}
