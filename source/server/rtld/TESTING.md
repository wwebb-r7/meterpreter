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

- [ ] stdapi library gets requested (no Failed to load extension exception)
- [ ] can use cat command to read a given file
- [ ] can upload /etc/passwd /tmp/passwd -> ensure files are the same
- [ ] can download /tmp/passwd /tmp/passwd -> ensure local /etc/passwd and /tmp/password are the same.
- [ ] can upload / download multiple files.
- [ ] can ls /etc/passwd and get reasonable results (especially given endianess, big endian fails)
- [ ] can ifconfig / arp / netstat / ps / etc and get reasonable results
- [ ] can execute commands ..
- [ ] can use networkpug 
- [ ] other features .. upgrade a shell to meterpreter session? for example!
- [ ] .. others .. ?



