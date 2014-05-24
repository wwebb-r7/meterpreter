VPATH=../../source/extensions/sniffer

OPENSSL=../../source/openssl/include
COMMON=../../source/common
SERVER=../../source/server
PCAP=../../posix-meterp-build-tmp/libpcap-1.5.3/

CFLAGS=-fPIC -DPIC -g -Wall
CFLAGS+=-D_UNIX
CFLAGS+=-I${COMMON} -I${SERVER} -I${OPENSSL} -I${PCAP} -I${VPATH}

LDFLAGS=-L$(COMPILED)

objects = sniffer.o

all: ext_server_sniffer.so

debug: CFLAGS+= -ggdb
debug: all

.c.o:
	$(CROSS)gcc $(CFLAGS) -c $<

ext_server_sniffer.so: $(objects)
	$(CROSS)gcc -shared $(CFLAGS) $(objects) -o $@ $(LDFLAGS) -lpcap -lcrypto -lssl -lmetsrv_main -lsupport

.PHONY: clean debug
clean:
	rm -f *.o *.so *~; rm -f $(objects)
