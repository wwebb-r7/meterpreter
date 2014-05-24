VPATH=../../source/extensions/networkpug

OPENSSL=../../source/openssl/include
COMMON=../../source/common
SERVER=../../source/server
PCAP=../../source/libpcap

CFLAGS=-fPIC -DPIC -Wall
CFLAGS+=-I$(COMMON) -I$(SERVER) -I$(OPENSSL) -I$(PCAP)
CFLAGS+= -I$(VPATH) -D_UNIX
LDFLAGS= -L$(COMPILED) -lpcap -lsupport -lmetsrv_main

objects = networkpug.o

all: ext_server_networkpug.so

debug: CFLAGS+= -ggdb
debug: all

.c.o:
	$(CROSS)gcc $(CFLAGS) -c $<

ext_server_networkpug.so: $(objects)
	$(CROSS)gcc -shared $(CFLAGS) $(objects) -o $@ $(LDFLAGS)


.PHONY: clean debug
clean:
	rm -f *.o *.so *~; rm -f $(objects)
