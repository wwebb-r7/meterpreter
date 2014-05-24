#ifndef ELFLOADER_H
#define ELFLOADER_H

#include <stdint.h>
#include <limits.h>
#include <sys/types.h>
#include "blob.h"
#include <elf.h>

#define ROUNDUP(x, y)   ((((x)+((y)-1))/(y))*(y))
#define	ALIGNDOWN(k, v)	((unsigned int)(k)&(~((unsigned int)(v)-1)))
#define ALIGN(k, v)     (((k)+((v)-1))&(~((v)-1)))

typedef struct loader {
	unsigned char *base;
	size_t length;
	unsigned char *next;
} loader_t;

int loader_alloc(loader_t *loader, size_t sz);
int load_elf_blob(loader_t *loader, blob_t *blob_in, blob_t *blob_out);

// below idea borrowed from musl-libc's dynlink.c
#if ULONG_MAX == 0xffffffff
	typedef Elf32_Ehdr Ehdr;
	typedef Elf32_Phdr Phdr;
#else
	typedef Elf64_Ehdr Ehdr;
	typedef Elf64_Phdr Phdr;
#endif

#endif

