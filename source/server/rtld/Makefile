
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

stage3: gzip2raw stage3.c
	$(CC) -Wall -ggdb -O2 -pie -fPIC -o stage3 stage3.c
	([ "$(DEBUG)" != "true" ] && $(STRIP) --strip-debug stage3) || true
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
	@echo "#define stage3_trap_handler_offset (0x`objdump -t stage3 | egrep text.*trap_handler | cut -d' ' -f1 `)" >> stage3.h
	@echo "#define stage3_detours_offset (0x`objdump -t stage3 | egrep bss.*detours | cut -d' ' -f1 `)" >> stage3.h
	@echo "#define stage3_libraries_offset (0x`objdump -t stage3 | egrep bss.*libraries | cut -d' ' -f1 `)" >> stage3.h
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

libc_offsets.h: libc.o
	@echo > libc_offsets.h
	#objdump -t $(compiled)/libc.so | egrep "text.* (open|close|fstat|mmap)(64)?$" | sed -r 's/\s+/ /g' | cut -d' ' -f 1,6 | while read off name ; do
	# echo "#define libc_${name}_offset (0x${offset})" >> libc_offsets.h \
	# done
	echo "#define libc_open_offset (0x`objdump -t $(compiled)/libc.so | egrep 'text.* open$$' | cut -d' ' -f 1`)" >> libc_offsets.h
	echo "#define libc_close_offset (0x`objdump -t $(compiled)/libc.so | egrep 'text.* close$$' | cut -d' ' -f 1`)" >> libc_offsets.h
	echo "#define libc_mmap_offset (0x`objdump -t $(compiled)/libc.so | egrep 'text.* mmap$$' | cut -d' ' -f 1`)" >> libc_offsets.h
	echo "#define libc_fstat_offset (0x`objdump -t $(compiled)/libc.so | egrep 'text.* fstat64$$' | cut -d' ' -f 1`)" >> libc_offsets.h
	echo "#define libc_read_offset (0x`objdump -t $(compiled)/libc.so | egrep 'text.* read$$' | cut -d' ' -f 1`)" >> libc_offsets.h
	echo "#define libc_pread_offset (0x`objdump -t $(compiled)/libc.so | egrep 'text.* pread$$' | cut -d' ' -f 1`)" >> libc_offsets.h

stage1.o: stage3 stage3.o

stage1: $(LIBOBJECTS) $(OBJ) stage1.c stage1.o stage3.o libc_offsets.h stage3
	$(CC) -static -Os -Wall -ggdb stage1.o stage3.o $(LIBOBJECTS) $(OBJ) -o stage1

.S.o:
	$(CC) $(CFLAGS) -c $<

.c.o:
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(OBJECTS)
	rm -f lib*.h
	rm -f *.o

.PHONY: clean

