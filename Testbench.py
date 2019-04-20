#!/usr/bin/python
import subprocess, os, sys

# 使用scapy 驗證
from scapy.all import *

# 啟動監聽器
sniffer_bash_command = './MySniffers4TCP 10 5'
sniffer_proc = subprocess.Popen(sniffer_bash_command, shell=True)

# 發送測試訊息
payload = "Hello, World!"
test_packet = IP(src="172.217.160.110", dst="172.217.160.110") / TCP(sport=9999, dport=80) / payload
send(test_packet)
send(test_packet)
send(test_packet)
send(test_packet)
send(test_packet)

sniffer_proc.wait()

# hexdump of payload
# 0000  48 65 6C 6C 6F 2C 20 57 6F 72 6C 64 21           Hello, World!
ans = '48 65 6C 6C 6F 2C 20 57 6F 72 6C 64 21'

# 比對紀錄
flag = False
print ('\nTesting...')
with open( './data.txt', mode='r') as data:
    for line in data:
        if line.strip() == ans:
            flag = True
if flag:
    print('Test Pass')
else:
    print('Test False')
