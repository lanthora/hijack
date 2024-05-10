#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
import os
import socket
import struct
import sys
import uuid

# 设置当前进程监听的端口,用于完成 Trace ID 的生成
event_tgid = int(sys.argv[1])  # 进程号
event_port = int(sys.argv[2])  # 该进程监听的端口

# 创建连接
client_file = '/tmp/hijack-{}.sock'.format(uuid.uuid4())
server_file = "/var/run/hijack-ctl.sock"
unix_domain_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
unix_domain_socket.bind(client_file)
unix_domain_socket.connect(server_file)

# 组装字节流并发送
bytes_to_send = struct.pack("=IiHi", 11, event_tgid, event_port, 0)
unix_domain_socket.send(bytes_to_send)

# 接收字节流并解析
bytes_to_unpack = unix_domain_socket.recv(len(bytes_to_send))
_, _, _, ret = struct.unpack("=IiHi", bytes_to_unpack)

# 打印结果
print(ret)

# 断开连接,清理资源
unix_domain_socket.close()
os.unlink(client_file)
