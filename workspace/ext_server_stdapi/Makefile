VPATH=../../source/extensions/stdapi
OPENSSL=../../source/openssl/include
COMMON=../../source/common
SERVER=../../source/server

CFLAGS=-fno-stack-protector -fPIC -DPIC -Wall
CFLAGS+=-D_UNIX -D__linux__
CFLAGS+=-I${COMMON} -I${SERVER} -I${OPENSSL}
CFLAGS+= -I../../source/extensions/stdapi/server

#-lsupport -lmetsrv_main

CFLAGS+= -Os

ifeq ($(OSNAME), FreeBSD)
	OS= bsd
else
	OS=$(OSNAME)
	CFLAGS+= -fno-stack-protector -D__linux__
endif

LDFLAGS=-L../../posix-meterp-build-tmp/compiled/ -lcrypto -lssl -lsupport -lmetsrv_main

objects = \
	server/fs/dir.o \
	server/fs/file.o \
	server/fs/fs_util.o \
	server/general.o \
	server/net/config/interface.o \
	server/net/config/route.o \
	server/net/config/arp.o \
	server/net/config/netstat.o \
	server/net/socket/tcp.o \
	server/net/socket/tcp_server.o \
	server/net/socket/udp.o \
	server/stdapi.o \
	server/sys/config/config.o \
	server/sys/process/process.o \
	server/sys/process/ps.o 

local_objects = \
	dir.o file.o fs_util.o general.o interface.o route.o arp.o \
	netstat.o tcp.o tcp_server.o udp.o stdapi.o config.o \
	process.o ps.o

	# server/sys/process/linux-in-mem-exe.o \

all: ext_server_stdapi.so

debug: CFLAGS+=-ggdb
debug: all

.c.o:
	$(CROSS)gcc $(CFLAGS) -c $<

ext_server_stdapi.so: $(objects)
	$(CROSS)gcc -shared $(CFLAGS) -o $@ $(local_objects) $(LDFLAGS)


.PHONY: clean debug
clean:
	rm -f *.o *.so *~
	rm -f $(objects) ext_server_stdapi.so

