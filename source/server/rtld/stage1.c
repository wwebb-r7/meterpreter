
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>

#include "libc.h"
#include "zlib.h"
#include "stage3.h"

void reset_signal_handlers();
void cleanup_fd();
int load_blob(unsigned char *start, unsigned int size, unsigned int raw_size);

int main(int argc, char **argv)
{

	printf("blob() .. start %08x\n", &libc_start); fflush(stdout);
	printf("blob() .. raw %08x\n", libc_raw); fflush(stdout);
	printf("blob() .. size %08x\n", &libc_size); fflush(stdout);
	/* 
	 * At this point, we're executing on an unknown stack, with an unknown
	 * stack size, so let's try to keep things as a minimum
	 * 
	 * XXX - it might be worth while having a "minstack" .data section
	 * stack variable, and moving our stack pointer to that. Investigate
	 * later.
	 */
	printf("reset()\n"); fflush(stdout);
	reset_signal_handlers();

	printf("clean()\n"); fflush(stdout);
	cleanup_fd();


	printf("blob() .. %08x, %08x, %08x\n", &libc_start, &libc_size, libc_raw); fflush(stdout);
	load_blob((unsigned char *)&libc_start, (int) &libc_size, libc_raw);

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
		return -1;
	}
	za->len = requested;

	return 0;
}


void *zalloc(void *opaque, unsigned int count, unsigned int size)
{
	struct zliballoc *za = opaque;
	size_t wanted;
	unsigned char *nextnext, *ret;

	// int wrap below.
	wanted = ((count * size) + 15) & ~15;
	
	printf("zalloc .. opaque is %p .. requesting %d bytes\n", opaque, wanted);

	nextnext = za->next + wanted;
	if(nextnext >= (za->base + za->len)) {
		// Please Sir, I want some more.
		//
		// If needed, we can mremap() the memory with MREMAP_FIXED
		// in order to ask for more memory at the same address.
		// However, I'll add that in if needed. 

		printf("requested a %d bytes, only %d bytes remaining\n", wanted, (int)(za->next) - (int)(za->base));
		fflush(stdout);
		*((unsigned char *)NULL) = 0;
		
		return NULL;
	}

	ret = za->next;
	za->next = nextnext;

	return ret;
}

void zfree(void *opaque, void *addr)
{
	struct zliballoc *za = opaque;

	printf("zfree .. opaque is %p\n", opaque);
}


int load_blob(unsigned char *start, unsigned int size, unsigned int raw_size)
{
	z_stream stream;
	struct zliballoc za;
	int status;

	unsigned char *input_buffer, output_buffer;
	size_t input_size, output_size;

	printf("in blob\n"); fflush(stdout);

	memset(&stream, 0, sizeof(z_stream));
	init_zliballoc(&za, raw_size/4); 

	output_size = (raw_size + 4095) & ~4095; 
	output_buffer = mmap(0, output_size, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	
	input_buffer = start;
	input_size = size;	
	
	stream.opaque = &za;
	stream.zalloc = zalloc;
	stream.zfree = zfree;
	stream.avail_in = input_size;
	stream.next_in = input_buffer;
	stream.avail_out = output_size;
	stream.next_out = output_buffer;

	printf("inflating ..\n"); fflush(stdout);
	inflateInit2(&stream, -MAX_WBITS);
	status = inflate(&stream, Z_FINISH);

	{
		int diff;

		diff = (int)(za.next) - (int) (za.base);
		printf("allocated %d bytes, used %d, remainder = %d\n", za.len, diff, za.len - diff);
	}
	
	if(status != Z_STREAM_END) {
		printf("decompression failed, status is %d\n", status); fflush(stdout);
		*((unsigned char *)NULL) = 0;
	}
	
	return 0;
}

