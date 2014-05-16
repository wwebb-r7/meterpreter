#ifndef BLOB_H
#define BLOB_H

#include <sys/types.h>

typedef struct blob {
	unsigned char *blob;
	size_t length;
	size_t alloc_size;
} blob_t;

int load_blob(unsigned char *start, unsigned int size, unsigned int raw_size, blob_t *blob);
void free_blob(blob_t *blob);

#endif
