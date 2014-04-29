
CFLAGS=-fPIC -DPIC

OBJ=zlib.o

compiled=../../../posix-meterp-build-tmp/compiled/

# These are all generated from their .so counterparts below
LIBOBJECTS=libc.o       \
	libpcap.o	\
	libcrypto.o      \
	libssl.o         \
	libsupport.o     \
	libmetsrv_main.o

all: stage1

debug: DEBUG=true
debug: CFLAGS+=-ggdb
debug: all

gzip2raw: gzip2raw.c
	gcc -Wall -ggdb -O2 gzip2raw.c -o gzip2raw

%.o: gzip2raw $(compiled)/%.so
	[ -d tmp ] || mkdir tmp
	cp $< tmp/$(*).tmp
	([ "$(DEBUG)" != "true" ] && $(STRIP) --strip-debug tmp/$(*).tmp) || true
	gzip -9nfc < tmp/$(*).tmp >tmp/$(*).gz
	./gzip2raw tmp/$(*).gz tmp/$(*).raw
	$(OBJCOPY) -I binary -O elf32-tradbigmips \
		--binary-architecture=mips \
		--redefine-sym _binary_tmp_$*_raw_start=$*_start \
		--redefine-sym _binary_tmp_$*_raw_end=$*_end \
		--redefine-sym _binary_tmp_$*_raw_size=$*_size \
		tmp/$(*).raw $(*).o
	@echo "extern int " $(*)"_start;" > $(*).h
	@echo "extern int " $(*)"_end;" >> $(*).h
	@echo "extern int " $(*)"_size;" >> $(*).h
	@echo "#define $(*)_raw (`stat -c'%s' tmp/$(*).raw`)" >> $(*).h
	rm tmp/$(*).*

stage1: $(LIBOBJECTS) $(OBJ)

.S.o:
	$(CC) $(CFLAGS) -c $<

.c.o:
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(OBJECTS)
	rm -f lib*.h
	rm -f *.o

.PHONY: clean

