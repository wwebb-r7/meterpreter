# POSIX meterpreter testing document

Note: This document is things that should be considered when designing a
testing regime - not what has been implemented, or what is planned to be
implemented.

## Stage 3 support

qemu can (most likely..) test the stage3 binary and libraries by using the
-E parameter to qemu - such as:

```
qemu-mips -E LD_LIBRARY_PATH=. ./stage3
```

Additionally, you can run it normally on a machine, and utilize standard
debugging tools present - such as valgrind for finding / isolating bugs,
since the libraries will be mmap()d in using standard library and kernel
interfaces.

XXX - It is probably a good idea to perform stage3 testing (of all the
below, used with address sanitizer to identify out of bounds memory
access).

## Compile Checklist

For when changes to meterpreter source code occurs

- [ ] Everything compiles
  - [ ] Perhaps we might want to ratchet down the warnings allowed over time, or at least disallow warnings.
- [ ] ... anything else? ...
  

## Runtime Checklist

- [ ] stage1 executes
  - [ ] allocates stack + new library mapping
  - [ ] decompresses libraries
  - [ ] userspace loads the libraries
  - [ ] sets up function hooking in the libc for dlopen support
    - [ ] store previous instructions
    - [ ] store address of fault
    - [ ] sets up signal handlers 
  - [ ] sets up the stack
  - [ ] performs the ld _start switchover
  - [ ] hands off execution to stage3

- [ ] stage3 runs
  - [ ] loads libpcap / openssl / libsupport / etc dependencies
  - [ ] enables debugging in libsupport
  - [ ] connects to metasploit metsvc_reverse_tcp ..
  - [ ] calls server_setup in libmetsrv_main

The above can implicitly be marked as passing once the connection to the
metasploit metsvc_reverse_tcp is made. From here onwards, metasploit
can be used to implement testing, I would imagine.

## Meterpreter Checklist

- [ ] Payloads offer the ability to turn on debugging, others. (fork() would be a good idea)
- [ ] Debugging log can be enabled, or disabled, and the /tmp/meterpreter.log.pid is created or not as expected.
- [ ] stdapi library gets requested (no Failed to load extension exception)

## stdapi Checklist

- [ ] can use cat command to read a given file
- [ ] can upload /etc/passwd /tmp/passwd -> ensure files are the same
- [ ] can download /tmp/passwd /tmp/passwd -> ensure local /etc/passwd and /tmp/password are the same.
- [ ] can upload / download multiple files.
- [ ] can ls /etc/passwd and get reasonable results (especially given endianess, big endian fails)
- [ ] can ifconfig / arp / netstat / ps / etc and get reasonable results
- [ ] can execute commands ..
- [ ] can load networkpug
- [ ] other features .. upgrade a shell to meterpreter session? for example!
- [ ] Process exits when metasploit framework exits.
- [ ] .. others .. ?

## networkpug Checklist

- [ ] metasploit creates tun/tap dev
- [ ] traffic from remote system shows up in local tun/tap dev
- [ ] you can ifconfig the tun/tap npug device and ping remote computers
- [ ] traffic from local system to remote system gets sent on the remote device
- [ ] can stop networkpug, meterpreter still runs
- [ ] xxx, others?

## sniffer Checklist

- [ ] sniffer_interfaces
- [ ] sniffer_start
 - [ ] sniffer_start <interface> 
 - [ ] sniffer_start <interface> packet capture size
 - [ ] sniffer_start <interface> packet capture size "bpf filter"
 - [ ] discard packets
 - [ ] sniffer_dump
- [ ] sniffer_stop

# Future testing ideas

- AddressSanitizer support
- ThreadSanitizer support (might require too much annotation ...)
- -Wall, -Wextra no outputs
- Compiles cleanly with clang as well
- Others?


