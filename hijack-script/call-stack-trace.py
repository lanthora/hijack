#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
import os
import socket
import struct
import sys
import uuid

# 开启打印函数调用栈功能
retprobe = int(sys.argv[1])  # 是否是在函数返回时触发
pid = int(sys.argv[2])  # 被 hook 的进程号
func_offset = int(sys.argv[3])  # 函数地址在可执行文件中的偏移量
binary_path = sys.argv[4]  # 被 hook 的二进制路径

# 创建连接
client_file = '/tmp/hijack-{}.sock'.format(uuid.uuid4())
server_file = "/var/run/hijack-ctl.sock"
unix_domain_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
unix_domain_socket.bind(client_file)
unix_domain_socket.connect(server_file)

# 组装字节流并发送
bytes_to_send = struct.pack("=IiiQ4096si", 9, retprobe, pid, func_offset, str.encode(binary_path), 0)
unix_domain_socket.send(bytes_to_send)

# 接收字节流并解析
bytes_to_unpack = unix_domain_socket.recv(len(bytes_to_send))
_, _, _, _, _, ret = struct.unpack("=IiiQ4096si", bytes_to_unpack)

# 打印结果
print(ret)

# 断开连接,清理资源
unix_domain_socket.close()
os.unlink(client_file)
