#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
import os
import socket
import struct
import sys
import uuid

# 开关 kfree_skb tracepoint
event_enabled = int(sys.argv[1])  # 是否启用

# 创建连接
client_file = '/tmp/hijack-{}.sock'.format(uuid.uuid4())
server_file = "/var/run/hijack-ctl.sock"
unix_domain_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
unix_domain_socket.bind(client_file)
unix_domain_socket.connect(server_file)

# 组装字节流并发送
bytes_to_send = struct.pack("=Iii", 5, event_enabled, 0)
unix_domain_socket.send(bytes_to_send)

# 接收字节流并解析
bytes_to_unpack = unix_domain_socket.recv(len(bytes_to_send))
_, _, ret = struct.unpack("=Iii", bytes_to_unpack)

# 打印结果
print(ret)

# 断开连接,清理资源
unix_domain_socket.close()
os.unlink(client_file)
