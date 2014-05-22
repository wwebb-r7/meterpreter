#include <string.h>
#include <sys/mman.h>
#include <elf.h>
#include <stdio.h>
#include <sys/types.h>
#include <elf.h>
#include <unistd.h>

#include "crash.h"
#include "elfloader.h"
#include "blob.h"

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

int load_elf_blob(loader_t *loader, blob_t *blob_in, blob_t *blob_out)
{
	Ehdr *ehdr;
	Phdr *phdr;
	int i;
	size_t filesz, memsz;
	static int page_size;

	if(page_size == 0) {
		page_size = sysconf(_SC_PAGESIZE);
	}

	ehdr = (Ehdr *)blob_in->blob;
	phdr = (Phdr *)(blob_in->blob + ehdr->e_phoff);

	if((int)(loader->next) & (page_size-1)) crash();

	/*
	 * Sanity checking?
	 *   Especially make sure all modules have same OS/platform/endian?
	 *   That might be a Makefile time thing, perhaps
	 */

	memset(blob_out, 0, sizeof(blob_t));
	// blob_out->blob = loader->next; // XXX

	printf("ehdr is at %p, and phdr is at %p\n", ehdr, phdr);
	for(i = 0; i < ehdr->e_phnum; i++, phdr++) {
		unsigned char *dst, *src;
		if(phdr->p_type != PT_LOAD) continue;

		if(! blob_out->blob) {
			size_t diff;

			blob_out->blob = (unsigned char *) ALIGN((size_t)(loader->next), (phdr->p_align));
			diff = (size_t)(blob_out->blob) - (size_t)(loader->next);
			loader->next += diff;
			// blob_out->blob = loader->next + diff;

			printf("Lost %d bytes due to page alignment :/\n", diff);
		}

		// map_addr = (void *)ALIGNDOWN(p->p_vaddr, p->p_align);

		printf("Found a PT_LOAD segment at %d\n", i);

		//offsz = phdr->p_vaddr & ~4095;
		filesz = phdr->p_filesz; // + (phdr->p_vaddr & 4095);

		//
		// adding in rounding up before ROUNDUP because of libcrypto,
		// libssl having a lot of .bss data
		//

		memsz = (phdr->p_memsz + (page_size-1)) & -page_size;
		memsz = ROUNDUP(memsz, phdr->p_align);
		if(phdr->p_vaddr) {
			// libcrypto corrupts libssl .text in dlopen, so
			// we add an extra page in here to work around this
			// issue until I can find the proper cause later on.
			memsz += page_size;
		}
		//memsz = ROUNDUP(phdr->p_memsz, phdr->p_align);

		if(filesz > memsz) {
			printf("Something is rotten in the state of Denmark\n");
			crash();
		}

		//dst = blob_out->blob + offsz;
		dst = blob_out->blob + phdr->p_vaddr;
		src = blob_in->blob + phdr->p_offset; // (phdr->p_offset & ~4096);
	
		printf("  memcpy(%p, %p, %d)\n", dst, src, filesz);

		//memcpy(blob_out->blob + offsz, blob_in->blob + (phdr->p_offset & ~4095), filesz);
		memcpy(dst, src, filesz);

		loader->next += memsz;
		blob_out->length += memsz;
	}

	return 0;
}

