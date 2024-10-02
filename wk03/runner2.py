from pwn import *

p = process(["qemu-x86_64", "-g", "1234", "./runner"])
context.arch = "amd64"

payload = asm("""
mov rbx, 30
mov rcx, 17
lea rax, [rbx*2 + rcx]
cmp rax, 50
jg crash1
mov rbx, [rbx]

crash1:
mov rax, [rax]

""")

p.sendlineafter(b"\n", payload)
p.interactive()