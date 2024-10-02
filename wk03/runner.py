import pwnlib.shellcraft.registers
from pwn import *
from pwnlib.adb import shell

p = process("./runner")

context.arch = "amd64"

hello_world = b"HELLO WORLD!!!"

hello_world_full = hello_world + b"\0" * (8 - len(hello_world) % 8)

chunk1 = hex(u64(hello_world_full[0:8]))
chunk2 = hex(u64(hello_world_full[8:16]))


pwnlib.shellcraft.amd64.sh()

payload = asm(f"""
    mov rdi, 1
    
    mov r8, {chunk2}
    push r8
    
    mov r8, {chunk1}
    push r8
    
    mov rsi, rsp
    
    mov rdx, {len(hello_world)}
    
    mov rax, SYS_write
    syscall
""")

p.sendlineafter(b"\n", payload)
p.interactive()