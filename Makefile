

# Used by 'install' target. Change this to wherever your framework checkout is.
# Doesn't have to be development. Should point to the base directory where
# msfconsole lives.
framework_dir = ../metasploit-framework/

# Change me if you want to build openssl and libpcap somewhere else
build_tmp = posix-meterp-build-tmp
cwd=$(shell pwd)

# Change me if you want to store dependencies somewhere else
build_dep = posix-meterp-build-dep

BUILDARCH=$(uname -m)-$(file /bin/ls | grep -o '[ML]SB')

PCAP_HOST=mips-linux


ROOT=$(basename $(CURDIR:%/=%))

COMPILED=${ROOT}/${build_tmp}/compiled

objects = $(COMPILED)/libpcap.so
objects += $(COMPILED)/libcrypto.so
objects += $(COMPILED)/libssl.so
objects += $(COMPILED)/libsupport.so
objects += $(COMPILED)/libmetsrv_main.so

outputs  = data/meterpreter/msflinker_linux_x86.bin
outputs += data/meterpreter/ext_server_stdapi.lso
outputs += data/meterpreter/ext_server_sniffer.lso
outputs += data/meterpreter/ext_server_networkpug.lso

workspace = workspace

all: $(objects) $(outputs)

debug: DEBUG=true
# I'm 99% sure this is the wrong way to do this
debug: MAKE += debug
debug: all

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

extract_mips_compiler:
	[ -d $(build_tmp)/mips-linux-musl ] || tar xJvf $(build_dep)/crossx86-mips-linux-musl-1.0.0.tar.xz -C $(build_tmp)

extract_arm_compiler:
	[ -d $(build_tmp)/arm-linux-musleabi ] || tar xJvf $(build_dep)/crossx86-arm-linux-musleabi-1.0.0.tar.xz -C $(build_tmp)

extract_ppc_compiler:
	[ -d $(build_tmp)/powerpc-linux-musl ] || tar xJvf $(build_dep)crossx86-powerpc-linux-musl-1.0.0.tar.xz -C $(build_tmp)

$(COMPILED): dependencies extract_mips_compiler extract_arm_compiler extract_ppc_compiler build_tmp
	[ -d $(COMPILED)/ ] || mkdir $(COMPILED)/

$(COMPILED)/libcrypto.so: $(build_tmp)/openssl-1.0.1g/libssl.so
	cp $(build_tmp)/openssl-1.0.1g/libcrypto.so $(COMPILED)/libcrypto.so

$(COMPILED)/libssl.so: $(build_tmp)/openssl-1.0.1g/libssl.so
	cp $(build_tmp)/openssl-1.0.1g/libssl.so $(COMPILED)/libssl.so

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
	(cd $(build_tmp)/libpcap-1.5.3 && CC="${CROSS}gcc" AR="${CROSS}ar" RANLIB="${CROSS}ranlib" LD="${CROSS}ld" MAKEDEPPROG="${CROSS}gcc"  ./configure --host=$(PCAP_HOST)  --with-pcap=linux --disable-bluetooth --without-bluetooth --without-usb --disable-usb --without-can --disable-can --without-usb-linux --disable-usb-linux --without-libnl)
	echo '#undef HAVE_DECL_ETHER_HOSTTON' >> $(build_tmp)/libpcap-1.5.3/config.h
	echo '#undef HAVE_SYS_BITYPES_H' >> $(build_tmp)/libpcap-1.5.3/config.h
	echo '#undef PCAP_SUPPORT_CAN' >> $(build_tmp)/libpcap-1.5.3/config.h
	echo '#undef PCAP_SUPPORT_USB' >> $(build_tmp)/libpcap-1.5.3/config.h
	echo '#undef HAVE_ETHER_HOSTTON'  >> $(build_tmp)/libpcap-1.5.3/config.h
	# echo '#define _STDLIB_H this_works_around_malloc_definition_in_grammar_dot_c' >> $(build_tmp)/libpcap-1.5.3/config.h
	(cd $(build_tmp)/libpcap-1.5.3 && patch -p0 < $(cwd)/source/libpcap/pcap_nametoaddr_fix.diff)
	sed -i -e s/pcap-usb-linux.c//g -e s/fad-getad.c/fad-gifc.c/g $(build_tmp)/libpcap-1.5.3/Makefile
	$(MAKE) -C $(build_tmp)/libpcap-1.5.3


data/meterpreter/msflinker_linux_x86.bin: source/server/rtld/msflinker.bin
	cp source/server/rtld/msflinker.bin data/meterpreter/msflinker_linux_x86.bin

source/server/rtld/msflinker.bin:
	$(MAKE) -C source/server/rtld

$(workspace)/metsrv/libmetsrv_main.so: $(COMPILED)/libsupport.so
	$(MAKE) -C $(workspace)/metsrv

$(COMPILED)/libmetsrv_main.so: $(workspace)/metsrv/libmetsrv_main.so
	cp $(workspace)/metsrv/libmetsrv_main.so $(COMPILED)/libmetsrv_main.so

$(workspace)/common/libsupport.so:
	$(MAKE) -C $(workspace)/common CC="${CROSS}gcc" AR="${CROSS}ar" RANLIB="${CROSS}ranlib" LD="${CROSS}ld" MAKEDEPPROG="${CROSS}gcc"

$(COMPILED)/libsupport.so: $(workspace)/common/libsupport.so
	cp $(workspace)/common/libsupport.so $(COMPILED)/libsupport.so

$(workspace)/ext_server_sniffer/ext_server_sniffer.so: $(COMPILED)/libpcap.so
	$(MAKE) -C $(workspace)/ext_server_sniffer

data/meterpreter/ext_server_sniffer.lso: $(workspace)/ext_server_sniffer/ext_server_sniffer.so
	cp $(workspace)/ext_server_sniffer/ext_server_sniffer.so data/meterpreter/ext_server_sniffer.lso

$(workspace)/ext_server_stdapi/ext_server_stdapi.so:
	$(MAKE) -C $(workspace)/ext_server_stdapi

data/meterpreter/ext_server_stdapi.lso: $(workspace)/ext_server_stdapi/ext_server_stdapi.so
	cp $(workspace)/ext_server_stdapi/ext_server_stdapi.so data/meterpreter/ext_server_stdapi.lso

$(workspace)/ext_server_networkpug/ext_server_networkpug.so:
	$(MAKE) -C $(workspace)/ext_server_networkpug

data/meterpreter/ext_server_networkpug.lso: $(workspace)/ext_server_networkpug/ext_server_networkpug.so
	cp $(workspace)/ext_server_networkpug/ext_server_networkpug.so data/meterpreter/ext_server_networkpug.lso


install: $(outputs)
	cp $(outputs) $(framework_dir)/data/meterpreter/

clean:
	rm -f $(objects)
	make -C source/server/rtld/ clean
	make -C $(workspace) clean

depclean:
	rm -f source/bionic/lib*/*.o
	find source/bionic/ -name '*.a' -print0 | xargs -0 rm -f 2>/dev/null
	find source/bionic/ -name '*.so' -print0 | xargs -0 rm -f 2>/dev/null
	rm -f source/bionic/lib*/*.so
	rm -rf source/openssl/lib/linux/i386/
	rm -rf $(build_tmp)

clean-pcap:
	#(cd $(build_tmp)/libpcap-1.5.3/ && make clean)
	# This avoids the pcap target trying to patch the same file more than once.
	# It's a pretty small tar, so untar'ing goes pretty quickly anyway, in
	# contrast to openssl.
	rm -r $(build_tmp)/libpcap-1.5.3 || true

clean-ssl:
	make -C $(build_tmp)/openssl-1.0.1g/ clean



really-clean: clean clean-ssl clean-pcap depclean


.PHONY: clean clean-ssl clean-pcap really-clean debug

