VPATH=../../source/extensions/sniffer

OPENSSL=../../source/openssl/include
COMMON=../../source/common
SERVER=../../source/server

CFLAGS=-fPIC -DPIC -g -Wall
CFLAGS+=-D_UNIX
CFLAGS+=-I${COMMON} -I${SERVER} -I${OPENSSL} -I${VPATH}

LDFLAGS=-L$(COMPILED)

objects = sniffer.o

all: posix_sample.so

debug: CFLAGS+= -ggdb
debug: all

.c.o:
	$(CROSS)gcc $(CFLAGS) -c $<

posix_sample.so: $(objects)
	$(CROSS)gcc -shared $(CFLAGS) $(objects) -o $@ $(LDFLAGS) -lpcap -lcrypto -lssl -lmetsrv_main -lsupport

# And, once done:
# copy posix_sample.so to data/meterpreter/ext_server_posix_sample.lso and "use posix_sample"

.PHONY: clean debug
clean:
	rm -f *.o *.so *~; rm -f $(objects)
