#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>

#include "zlib.h"

static int const gz_magic[2] = {0x1f, 0x8b}; /* gzip magic header */

/* gzip flag byte */
#define ASCII_FLAG   0x01 /* bit 0 set: file probably ascii text */
#define HEAD_CRC     0x02 /* bit 1 set: header CRC present */
#define EXTRA_FIELD  0x04 /* bit 2 set: extra field present */
#define ORIG_NAME    0x08 /* bit 3 set: original file name present */
#define COMMENT      0x10 /* bit 4 set: file comment present */
#define RESERVED     0xE0 /* bits 5..7: reserved */


#define    EOF     (-1)
/* ===========================================================================
      Check the gzip header of a gz_stream opened for reading. Set the stream
    mode to transparent if the gzip magic header is not present; set s->err
    to Z_DATA_ERROR if the magic header is present but the rest of the header
    is incorrect.
    IN assertion: the stream s has already been created sucessfully;
       s->stream.avail_in is zero for the first time, but may be non-zero
       for concatenated .gz files.
*/
static int
check_header(unsigned char **input_buffer, size_t *input_length)
{
    int method; /* method byte */
    int flags;  /* flags byte */
    int c;
    int len = *input_length;
    unsigned char *inbuf = *input_buffer;

    if (len < 2) 
	    return Z_DATA_ERROR;

    if (inbuf[0] != gz_magic[0] ||
        inbuf[1] != gz_magic[1])
	    return Z_DATA_ERROR;

    len -= 2;
    inbuf += 2;

    /* Check the rest of the gzip header */
    method = inbuf[0];
    flags = inbuf[1];
    if (method != Z_DEFLATED || (flags & RESERVED) != 0)
	    return Z_DATA_ERROR;
    
    /* Discard time, xflags and OS code: */
    inbuf += 8;
    len -= 8;

    if ((flags & EXTRA_FIELD) != 0) { /* skip the extra field */
	    int field_len  =  (uInt)inbuf[0];
	    field_len += ((uInt)inbuf[1])<<8;
	    inbuf += 2;
	    len -= 2;
	    /* len is garbage if EOF but the loop below will quit anyway */
	    while (field_len-- != 0 && *(int *)inbuf != EOF) {
		    inbuf++;
		    len--;
	    }
    }
    /*
     * note that the original name skipping logics seems to be buggy
     *
     */
    if ((flags & ORIG_NAME) != 0) { /* skip the original file name */
	    while ((c = *inbuf) != 0 && c != EOF) {
		    inbuf++;
		    len--;
	    }
	    inbuf++;
	    len--;
    }
    if ((flags & COMMENT) != 0) {   /* skip the .gz file comment */
	    while ((c = *inbuf) != 0 && c != EOF) {
		    inbuf++;
		    len--;
	    }
    }
    if ((flags & HEAD_CRC) != 0) {  /* skip the header crc */
	    inbuf += 2;
	    len -= 2;
    }

    *input_length = len;
    *input_buffer = inbuf;
    return Z_OK;
}

struct filemap {
	int fd;
	unsigned char *base;
	size_t length;
};

struct filemap *load_file(char *input)
{
	struct filemap *fm;
	struct stat statbuf;

	fm = calloc(1, sizeof(struct filemap));
	if(! fm) { 
		printf("Really?\n");
		exit(EXIT_FAILURE);
	}

	fm->fd = open(input, O_RDONLY);
	if(fm->fd == -1) {
		printf("Unable to open %s: %s\n", input, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if(fstat(fm->fd, &statbuf) == -1) {
		printf("Unable to fstat(%d): %s\n", fm->fd, strerror(errno));
		exit(EXIT_FAILURE);
	}

	fm->length = statbuf.st_size;
	fm->base = mmap(NULL, fm->length, PROT_READ|PROT_WRITE, MAP_PRIVATE, fm->fd, 0);
	
	if(fm->base == MAP_FAILED) {
		printf("Unable to mmap %ld bytes from %s: %s\n", fm->length, input, strerror(errno));
		exit(EXIT_FAILURE);
	}

	return fm;

}

int main(int argc, char **argv)
{
	struct filemap *fm;
	int ofd;
	unsigned char *tmp_b;
	size_t tmp_l;
	int ret;

	if(argc != 3) {
		printf("gzip2raw <input filename> <output filename>\n");
		exit(EXIT_FAILURE);
	}

	fm = load_file(argv[1]);
	if(fm == NULL) {
		printf("Failed loading input file\n");
		exit(EXIT_FAILURE);
	}

	tmp_b = fm->base;
	tmp_l = fm->length;

	if((ret = check_header(&tmp_b, &tmp_l)) != Z_OK) {
		printf("Input isn't compressed (check_header returned %s)\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	ofd = open(argv[2], O_WRONLY|O_TRUNC|O_CREAT, 0644);
	if(ofd == -1) {
		printf("Opening output file %s failed: %s\n", argv[2], strerror(errno));
		exit(EXIT_FAILURE);
	}

	if((ret = write(ofd, tmp_b, tmp_l)) != tmp_l) {
		printf("Unable to write output: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	close(ofd);

	return 0;	
}

