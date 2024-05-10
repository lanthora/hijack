#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
import os
import socket
import struct
import sys
import uuid

# 创建与每个进程相关的配置.例如要打开或关闭与进程相关的 IO 事件,需要先在这里创建与每个进程相关的配置
event_tgid = int(sys.argv[1])  # 进程号
event_enabled = int(sys.argv[2])  # 是否启用这个配置

# 创建连接
client_file = '/tmp/hijack-{}.sock'.format(uuid.uuid4())
server_file = "/var/run/hijack-ctl.sock"
unix_domain_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
unix_domain_socket.bind(client_file)
unix_domain_socket.connect(server_file)

# 组装字节流并发送
bytes_to_send = struct.pack("=Iiii", 4, event_tgid, event_enabled, 0)
unix_domain_socket.send(bytes_to_send)

# 接收字节流并解析
bytes_to_unpack = unix_domain_socket.recv(len(bytes_to_send))
_, _, _, ret = struct.unpack("=Iiii", bytes_to_unpack)

# 打印结果
print(ret)

# 断开连接,清理资源
unix_domain_socket.close()
os.unlink(client_file)
