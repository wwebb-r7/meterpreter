
CFLAGS=-fPIC -DPIC -Wall -ggdb 

OBJ=zlib.o

compiled=../../../posix-meterp-build-tmp/compiled/

# These are all generated from their .so counterparts below
LIBOBJECTS=libc.o       \
	libpcap.o	\
	libcrypto.o      \
	libssl.o         \
	libsupport.o     \
	libmetsrv_main.o

all: stage3 stage1

debug: DEBUG=true
debug: CFLAGS+=-ggdb
debug: all

gzip2raw: gzip2raw.c
	gcc -Wall -ggdb -O2 gzip2raw.c -o gzip2raw

stage3: gzip2raw
	$(CC) -Wall -ggdb -O2 -o stage3 stage3.c
	gzip -9nfc < stage3 >stage3.gz
	./gzip2raw stage3.gz stage3.raw
	$(OBJCOPY) -I binary -O elf32-tradbigmips \
		--binary-architecture=mips \
		--redefine-sym _binary_stage3_raw_start=stage3_start \
		--redefine-sym _binary_stage3_raw_end=stage3_end \
		--redefine-sym _binary_stage3_raw_size=stage3_size \
		stage3.raw stage3.o
	@echo "extern int " stage3"_start;" > stage3.h
	@echo "extern int " stage3"_end;" >> stage3.h
	@echo "extern int " stage3"_size;" >> stage3.h
	@echo "#define stage3_raw (`stat -c'%s' stage3`)" >> stage3.h
	rm stage3.raw stage3.gz

%.o: $(compiled)/%.so
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
	@echo "#define $(*)_raw (`stat -c'%s' tmp/$(*).tmp`)" >> $(*).h
	rm tmp/$(*).*

stage1: $(LIBOBJECTS) $(OBJ) stage1.o stage3.o
	$(CC) -Wall -ggdb -static stage1.o stage3.o $(LIBOBJECTS) $(OBJ) -o stage1

.S.o:
	$(CC) $(CFLAGS) -c $<

.c.o:
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(OBJECTS)
	rm -f lib*.h
	rm -f *.o

.PHONY: clean

