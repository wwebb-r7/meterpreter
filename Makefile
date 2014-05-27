

# Used by 'install' target. Change this to wherever your framework checkout is.
# Doesn't have to be development. Should point to the base directory where
# msfconsole lives.
framework_dir = ../metasploit-framework/

# Change me if you want to build openssl and libpcap somewhere else
build_tmp = posix-meterp-build-tmp
cwd=$(shell pwd)

# Change me if you want to store dependencies somewhere else
build_dep = posix-meterp-build-dep

ROOT=$(basename $(CURDIR:%/=%))

COMPILED=${ROOT}/${build_tmp}/compiled

objects = $(COMPILED)/libpcap.so
objects += $(COMPILED)/libcrypto.so
objects += $(COMPILED)/libssl.so
objects += $(COMPILED)/libsupport.so
objects += $(COMPILED)/libmetsrv_main.so

outputs  = data/meterpreter/posix_meterpreter_stage1_${METARCH}.bin
outputs += data/meterpreter/ext_server_stdapi.${METARCH}lso
outputs += data/meterpreter/ext_server_sniffer.${METARCH}lso
outputs += data/meterpreter/ext_server_networkpug.${METARCH}lso

workspace = workspace

all: $(COMPILED) $(objects) $(outputs)

debug: DEBUG=true
# I'm 99% sure this is the wrong way to do this
debug: MAKE += debug
debug: all


# When you see something about it most likely not being the right
# way to do things, do you a) research the proper way to do things
# (which probably involves including files), or b) it works, so it
# must be the correct way to do things?

x86: CROSS=${ROOT}/${build_tmp}/i486-linux-musl/bin/i486-linux-musl-
x86: OPENSSL_TARGET=linux-generic32
x86: BFD_TARGET=elf32-i386
x86: BINARY_ARCHITECTURE=i386
x86: PLATFORM_FILE=i486
x86: PCAP_HOST=i386-linux
x86: METARCH=x86
x86: copy_i486_libc all

mipsbe: CROSS=${ROOT}/${build_tmp}/mips-linux-musl/bin/mips-linux-musl-
mipsbe: OPENSSL_TARGET=linux-generic32
mipsbe: BFD_TARGET=elf32-tradbigmips
mipsbe: BINARY_ARCHITECTURE=mips
mipsbe: PLATFORM_FILE=mipsbe
mipsbe: PCAP_HOST=mips-linux
mipsbe: METARCH=mipsbe
mipsbe: copy_mips_libc all

x64: CROSS=${ROOT}/${build_tmp}/x86_64-linux-musl/bin/x86_64-linux-musl-
x64: OPENSSL_TARGET=linux-x86_64
x64: BFD_TARGET=elf64-x86-64
x64: BINARY_ARCHITECTURE=i386
x64: PLATFORM_FILE=x86_64
x64: PCAP_HOST=x86_64-linux
x64: METARCH=x64
x64: copy_x86_64_libc all

ppc: CROSS=${ROOT}/${build_tmp}/powerpc-linux-musl/bin/powerpc-linux-musl-
ppc: OPENSSL_TARGET=linux-generic32
ppc: BFD_TARGET=elf32-powerpc
ppc: PCAP_HOST=powerpc-linux
ppc: BINARY_ARCHITECTURE=powerpc
ppc: PLATFORM_FILE=ppc
ppc: METARCH=ppc
ppc: copy_ppc_libc all

armle: CROSS=${ROOT}/${build_tmp}/arm-linux-musleabi/bin/arm-linux-musleabi-
armle: OPENSSL_TARGET=linux-generic32
armle: BFD_TARGET=elf32-littlearm
armle: PCAP_HOST=arm-linux
armle: BINARY_TARGET=arm
armle: PLATFORM_FILE=arm
armle: METARCH=armle
armle: copy_arm_libc all

$(build_dep):
	[ -d $(build_dep) ] || mkdir $(build_dep)/

build_tmp:
	[ -d $(build_tmp) ] || mkdir $(build_tmp)/

dependencies: $(build_dep)
	[ -f $(build_dep)/openssl-1.0.1g.tar.gz ] || wget -O $(build_dep)/openssl-1.0.1g.tar.gz https://www.openssl.org/source/openssl-1.0.1g.tar.gz
	[ -f $(build_dep)/libpcap-1.5.3.tar.gz ] || wget -O $(build_dep)/libpcap-1.5.3.tar.gz http://www.tcpdump.org/release/libpcap-1.5.3.tar.gz
	[ -f $(build_dep)/crossx86-mips-linux-musl-1.0.0.tar.xz ] || wget -O $(build_dep)/crossx86-mips-linux-musl-1.0.0.tar.xz https://googledrive.com/host/0BwnS5DMB0YQ6bDhPZkpOYVFhbk0/musl-1.0.0/crossx86-mips-linux-musl-1.0.0.tar.xz
	[ -f $(build_dep)/crossx86-arm-linux-musleabi-1.0.0.tar.xz ] || wget -O $(build_dep)/crossx86-arm-linux-musleabi-1.0.0.tar.xz https://googledrive.com/host/0BwnS5DMB0YQ6bDhPZkpOYVFhbk0/musl-1.0.0/crossx86-arm-linux-musleabi-1.0.0.tar.xz
	[ -f $(build_dep)/crossx86-powerpc-linux-musl-1.0.0.tar.xz ] || wget -O $(build_dep)/crossx86-powerpc-linux-musl-1.0.0.tar.xz https://googledrive.com/host/0BwnS5DMB0YQ6bDhPZkpOYVFhbk0/musl-1.0.0/crossx86-powerpc-linux-musl-1.0.0.tar.xz
	[ -f $(build_dep)/crossx86-x86_64-linux-musl-1.0.0.tar.xz ] || wget -O $(build_dep)/crossx86-x86_64-linux-musl-1.0.0.tar.xz https://googledrive.com/host/0BwnS5DMB0YQ6bDhPZkpOYVFhbk0/musl-1.0.0/crossx86-x86_64-linux-musl-1.0.0.tar.xz
	[ -f $(build_dep)/crossx86-i486-linux-musl-1.0.0.tar.xz ] || wget -O $(build_dep)/crossx86-i486-linux-musl-1.0.0.tar.xz https://googledrive.com/host/0BwnS5DMB0YQ6bDhPZkpOYVFhbk0/musl-1.0.0/crossx86-i486-linux-musl-1.0.0.tar.xz

extract_mips_compiler:
	[ -d $(build_tmp)/mips-linux-musl ] || tar xJvf $(build_dep)/crossx86-mips-linux-musl-1.0.0.tar.xz -C $(build_tmp)

extract_arm_compiler:
	[ -d $(build_tmp)/arm-linux-musleabi ] || tar xJvf $(build_dep)/crossx86-arm-linux-musleabi-1.0.0.tar.xz -C $(build_tmp)

extract_ppc_compiler:
	[ -d $(build_tmp)/powerpc-linux-musl ] || tar xJvf $(build_dep)/crossx86-powerpc-linux-musl-1.0.0.tar.xz -C $(build_tmp)

extract_x86_64_compiler:
	[ -d $(build_tmp)/x86_64-linux-musl ] || tar xJvf $(build_dep)/crossx86-x86_64-linux-musl-1.0.0.tar.xz -C $(build_tmp)

extract_i486_compiler:
	[ -d $(build_tmp)/i486-linux-musl ] || tar xJvf $(build_dep)/crossx86-i486-linux-musl-1.0.0.tar.xz -C $(build_tmp)

copy_mips_libc: $(COMPILED)
	cp $(build_tmp)/mips-linux-musl/mips-linux-musl/lib/libc.so ${COMPILED}/libc.so

copy_arm_libc: $(COMPILED)
	cp $(build_tmp)/arm-linux-musleabi/arm-linux-musleabi/lib/libc.so ${COMPILED}/libc.so

copy_ppc_libc: $(COMPILED)
	cp $(build_tmp)/powerpc-linux-musl/powerpc-linux-musl/lib/libc.so ${COMPILED}/libc.so

copy_x86_64_libc: $(COMPILED)
	cp $(build_tmp)/x86_64-linux-musl/x86_64-linux-musl/lib/libc.so $(COMPILED)/libc.so

copy_i486_libc: $(COMPILED)
	cp $(build_tmp)/i486-linux-musl/i486-linux-musl/lib/libc.so $(COMPILED)/libc.so


$(COMPILED): build_tmp dependencies extract_mips_compiler extract_arm_compiler extract_ppc_compiler extract_x86_64_compiler extract_i486_compiler
	[ -d $(COMPILED)/ ] || mkdir $(COMPILED)/

$(COMPILED)/libcrypto.so: $(build_tmp)/openssl-1.0.1g/libssl.so
	cp $(build_tmp)/openssl-1.0.1g/libcrypto.so $(COMPILED)/libcrypto.so

$(COMPILED)/libssl.so: $(build_tmp)/openssl-1.0.1g/libssl.so
	cp $(build_tmp)/openssl-1.0.1g/libssl.so $(COMPILED)/libssl.so

# linux-x86_64 needed for that for x86_64 ..

$(build_tmp)/openssl-1.0.1g/libssl.so:
	[ -d $(build_tmp) ] || mkdir $(build_tmp)
	[ -d $(build_tmp)/openssl-1.0.1g ] || tar -C $(build_tmp)/ -xzf $(build_dep)/openssl-1.0.1g.tar.gz
	(cd $(build_tmp)/openssl-1.0.1g &&                                                       \
		 CC="${CROSS}gcc" AR="${CROSS}ar" RANLIB="${CROSS}ranlib" LD="${CROSS}ld" MAKEDEPPROG="${CROSS}gcc" ./Configure --prefix=/tmp/out threads shared no-hw no-dlfcn no-zlib no-krb5 no-idea linux-generic32 && \
		patch -p1 < $(ROOT)/patches/linux-musl-libc-termios.patch \
	)
	(cd $(build_tmp)/openssl-1.0.1g && $(MAKE) depend all ; [ -f libssl.so.1.0.0 -a -f libcrypto.so.1.0.0 ] )

$(COMPILED)/libpcap.so: $(build_tmp)/libpcap-1.5.3/libpcap.so.1.5.3
	cp $(build_tmp)/libpcap-1.5.3/libpcap.so.1.5.3 $(COMPILED)/libpcap.so

$(build_tmp)/libpcap-1.5.3/libpcap.so.1.5.3:
	[ -d $(build_tmp) ] || mkdir $(build_tmp)
	[ -f $(build_tmp)/libpcap-1.5.3/configure ] || tar -C $(build_tmp) -xzf $(build_dep)/libpcap-1.5.3.tar.gz
	(cd $(build_tmp)/libpcap-1.5.3 && CC="${CROSS}gcc" AR="${CROSS}ar" RANLIB="${CROSS}ranlib" LD="${CROSS}ld" MAKEDEPPROG="${CROSS}gcc"  ./configure --host=${PCAP_HOST} --with-pcap=linux --disable-bluetooth --without-bluetooth --without-usb --disable-usb --without-can --disable-can --without-usb-linux --disable-usb-linux --without-libnl)
	echo '#undef HAVE_DECL_ETHER_HOSTTON' >> $(build_tmp)/libpcap-1.5.3/config.h
	echo '#undef HAVE_SYS_BITYPES_H' >> $(build_tmp)/libpcap-1.5.3/config.h
	echo '#undef PCAP_SUPPORT_CAN' >> $(build_tmp)/libpcap-1.5.3/config.h
	echo '#undef PCAP_SUPPORT_USB' >> $(build_tmp)/libpcap-1.5.3/config.h
	echo '#undef HAVE_ETHER_HOSTTON'  >> $(build_tmp)/libpcap-1.5.3/config.h
	# echo '#define _STDLIB_H this_works_around_malloc_definition_in_grammar_dot_c' >> $(build_tmp)/libpcap-1.5.3/config.h
	(cd $(build_tmp)/libpcap-1.5.3 && patch -p0 < $(cwd)/source/libpcap/pcap_nametoaddr_fix.diff)
	sed -i -e s/pcap-usb-linux.c//g -e s/fad-getad.c/fad-gifc.c/g $(build_tmp)/libpcap-1.5.3/Makefile
	$(MAKE) -C $(build_tmp)/libpcap-1.5.3


data/meterpreter/posix_meterpreter_stage1_${METARCH}.bin: source/server/rtld/stage1
	cp source/server/rtld/stage1 data/meterpreter/posix_meterpreter_stage1_${METARCH}.bin

source/server/rtld/stage1:
	$(MAKE) -C source/server/rtld PLATFORM_FILE=$(PLATFORM_FILE) CROSS=${CROSS} BFD_TARGET=${BFD_TARGET} BINARY_ARCHITECTURE=${BINARY_ARCHITECTURE}

$(workspace)/metsrv/libmetsrv_main.so: $(COMPILED)/libsupport.so
	$(MAKE) -C $(workspace)/metsrv CROSS=${CROSS}

$(COMPILED)/libmetsrv_main.so: $(workspace)/metsrv/libmetsrv_main.so
	cp $(workspace)/metsrv/libmetsrv_main.so $(COMPILED)/libmetsrv_main.so

$(workspace)/common/libsupport.so:
	$(MAKE) -C $(workspace)/common CROSS=${CROSS}

$(COMPILED)/libsupport.so: $(workspace)/common/libsupport.so
	cp $(workspace)/common/libsupport.so $(COMPILED)/libsupport.so

$(workspace)/ext_server_sniffer/ext_server_sniffer.so: $(COMPILED)/libpcap.so
	$(MAKE) -C $(workspace)/ext_server_sniffer CROSS=${CROSS} COMPILED=${COMPILED}

data/meterpreter/ext_server_sniffer.${METARCH}lso: $(workspace)/ext_server_sniffer/ext_server_sniffer.so
	cp $(workspace)/ext_server_sniffer/ext_server_sniffer.so data/meterpreter/ext_server_sniffer.${METARCH}lso

$(workspace)/ext_server_stdapi/ext_server_stdapi.so:
	$(MAKE) -C $(workspace)/ext_server_stdapi CROSS=${CROSS} COMPILED=${COMPILED}

data/meterpreter/ext_server_stdapi.${METARCH}lso: $(workspace)/ext_server_stdapi/ext_server_stdapi.so
	cp $(workspace)/ext_server_stdapi/ext_server_stdapi.so data/meterpreter/ext_server_stdapi.${METARCH}lso

$(workspace)/ext_server_networkpug/ext_server_networkpug.so:
	$(MAKE) -C $(workspace)/ext_server_networkpug CROSS=${CROSS} COMPILED=${COMPILED}

data/meterpreter/ext_server_networkpug.${METARCH}lso: $(workspace)/ext_server_networkpug/ext_server_networkpug.so
	cp $(workspace)/ext_server_networkpug/ext_server_networkpug.so data/meterpreter/ext_server_networkpug.${METARCH}lso


install: $(outputs)
	cp $(outputs) $(framework_dir)/data/meterpreter/

clean: METARCH=*
clean:
	rm -f $(objects)
	make -C source/server/rtld/ clean
	make -C $(workspace) clean
	rm -rf $(build_tmp)/compiled

cleaner: clean clean-pcap clean-ssl
	@echo "Who looks beautiful now?"

tmpclean:
	rm -rf $(build_tmp)

clean-pcap:
	#(cd $(build_tmp)/libpcap-1.5.3/ && make clean)
	# This avoids the pcap target trying to patch the same file more than once.
	# It's a pretty small tar, so untar'ing goes pretty quickly anyway, in
	# contrast to openssl.
	rm -r $(build_tmp)/libpcap-1.5.3 || true

clean-ssl:
	make -C $(build_tmp)/openssl-1.0.1g/ clean



really-clean: clean clean-ssl clean-pcap tmpclean


.PHONY: clean clean-ssl clean-pcap really-clean debug

