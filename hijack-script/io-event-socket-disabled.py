#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
import os
import socket
import struct
import sys
import uuid

# 关闭 Socket IO 事件,该功能默认开启
event_tgid = int(sys.argv[1])  # 本功能影响的进程
event_disabled = int(sys.argv[2])  # 是否禁用

# 创建连接
client_file = '/tmp/hijack-{}.sock'.format(uuid.uuid4())
server_file = "/var/run/hijack-ctl.sock"
unix_domain_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
unix_domain_socket.bind(client_file)
unix_domain_socket.connect(server_file)

# 组装字节流并发送
bytes_to_send = struct.pack("=Iiii", 3, event_tgid, event_disabled, 0)
unix_domain_socket.send(bytes_to_send)

# 接收字节流并解析
bytes_to_unpack = unix_domain_socket.recv(len(bytes_to_send))
_, _, _, ret = struct.unpack("=Iiii", bytes_to_unpack)

# 打印结果
print(ret)

# 断开连接,清理资源
unix_domain_socket.close()
os.unlink(client_file)
