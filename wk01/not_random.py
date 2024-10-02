from pwn import *

p = process("./not-random")

p.sendlineafter(b"!\n", b"246")
p.interactive()

0x10203040

p32(5)
u32(5)
p64(5)
u64(5)