.SUFFIXES: .S .c

SOURCEPATH=../../source/common
SSLPATH=../../source/openssl/include
MALLOC_PATH=../../source/common/malloc
XOR_PATH=../../source/common/crypto
STDLIBPATH=../../source/common/stdlib
ZLIB_PATH=../../source/common/zlib


# CFLAGS= -Dwchar_t="char"  -D_SIZE_T_DECLARED -DElf_Size="u_int32_t" -D_BYTE_ORDER=_LITTLE_ENDIAN
CFLAGS= -D_UNIX -I$(SOURCEPATH) -I$(MALLOC_PATH) -I$(XOR_PATH) -DMALLOC_PRODUCTION -DPIC -I$(SSLPATH) -I$(STDLIBPATH) -I$(ZLIB_PATH)
CFLAGS+= -g -fPIC -Os
CFLAGS+= -L../../posix-meterp-build-tmp/compiled/
# WTF IS THIS? -D_POSIX_C_SOURCE=200809 -D__BSD_VISIBLE=1 -D__XSI_VISIBLE=1
# CFLAGS+= -march=i386 -m32


objects = args.o base.o base_dispatch.o base_dispatch_common.o buffer.o \
	channel.o common.o core.o list.o remote.o thread.o xor.o zlib.o



####### check platform
OSNAME= $(shell uname -s)
ARCH= $(shell uname -m | sed 's/i[456]86/i386/g')

ifeq ($(OSNAME), FreeBSD)
	OS= bsd
	libc_objects+= cerror.o
else
	# WTF?
	#CFLAGS+= -fno-stack-protector -D__linux__
	#CFLAGS+=  -D_POSIX_C_SOURCE=200809 -D__BSD_VISIBLE=1 -D__XSI_VISIBLE=1
	#OS=$(OSNAME)
        OS=posix
#	requires tls - which we don't have
#	libc_objects+= errno.o
endif

BASEVPATH=../../source/common:../../source/common/crypto:../../source/common/arch/posix:../../source/common/zlib:
OSVPATH= ../../source/common/arch/$(OS)
ARCHVPATH= $(OSVPATH)/$(ARCH)
VPATH=$(BASEVPATH):$(OSVPATH):$(ARCHVPATH)

CFLAGS+= -I$(ARCHVPATH)


all: libsupport.so

debug: CFLAGS+=-ggdb
debug: all

.c.o:
	$(CROSS)gcc $(CFLAGS) -c $<

libsupport.so: $(objects)
	$(CROSS)gcc $(CFLAGS) -shared $(objects) -lssl -lcrypto -o $@

clean:
	rm -f *.o *.a *.so zlib/zlib.o

.PHONY: clean

