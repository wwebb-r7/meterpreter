
BASEVPATH=../../source/server:../../source/server/posix/
OPENSSL=../../source/openssl/include
COMMON=../../source/common
SERVER=../../source/server

CFLAGS=-fPIC -fno-stack-protector #-nostdinc -nostdlib 
CFLAGS+=-D_UNIX -D__linux__ 
CFLAGS+=-I${COMMON} -I${SERVER} -I${OPENSSL}
#CFLAGS+= -Dwchar_t="char" -fno-builtin -D_SIZE_T_DECLARED -DElf_Size="u_int32_t" 
#CFLAGS+= -D_BYTE_ORDER=_LITTLE_ENDIAN
#CFLAGS+= -lgcc -L../../source/bionic/compiled
CFLAGS+= -L../../posix-meterp-build-tmp/compiled
#CFLAGS+= -march=i386 -m32

OS=posix
OSVPATH=../../source/common/arch/$(OS):../../source/server/linux/
ARCHVPATH=$(OSVPATH)/$(RARCH):$(ELFARCHPATH)
VPATH=$(BASEVPATH):$(OSVPATH):$(ARCHVPATH)

ifeq ($(CC),cc)
	CC=gcc
endif

objects= metsrv.o scheduler.o 
objects+= server_setup.o remote_dispatch_common.o remote_dispatch.o netlink.o

all:  libmetsrv_main.so 

debug: CFLAGS+=-ggdb
debug: all

.c.o:
	$(CROSS)$(CC) $(CFLAGS) -c $<

libmetsrv_main.so: $(objects)
	$(CROSS)$(CC) -shared $(CFLAGS) -o $@ $(objects) -export-dynamic  -lcrypto -lssl  -lsupport

clean:
	@echo "ARCHVPATH= " $(ARCHVPATH) " VPATH= " $(VPATH)
	$(RM) -f *.o *.h *.so *.gz *~ *.a libmetsrv_main.so

.PHONY: clean
