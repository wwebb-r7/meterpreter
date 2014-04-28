
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

%.o: $(compiled)/%.so
	[ -d tmp ] || mkdir tmp
	cp $< tmp/$(*).tmp
	([ "$(DEBUG)" != "true" ] && $(STRIP) --strip-debug tmp/$(*).tmp) || true
	gzip -nfc < tmp/$(*).tmp >tmp/$(*).gz
	$(OBJCOPY) -I binary -O elf32-big \
		--redefine-sym _binary_tmp_$*_start=$*_start \
		--redefine-sym _binary_tmp_$*_end=$*_end \
		--redefine-sym _binary_tmp_$*_size=$*_size \
		tmp/$(*).gz $(*).o
	@echo "extern const char " $(*)"[];" > $(*).h
	@echo "extern const char " $(*)"_end[];" >> $(*).h
	@echo "extern const char " $(*)"_size_sym[];" >> $(*).h
	@echo "#define $(*)_size ((int)$(*)_size_sym)" >> $(*).h
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

