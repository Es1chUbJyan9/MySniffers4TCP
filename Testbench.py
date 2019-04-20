#!/usr/bin/python
import subprocess, os, sys

dns_bash_command = 'nslookup -vc google.com 8.8.8.8'
sniffer_bash_command = './MySniffers4TCP.out 10 5'

sniffer_proc = subprocess.Popen(sniffer_bash_command, shell=True)
dns_proc = subprocess.Popen(dns_bash_command, shell=True)

sniffer_proc.wait()


print ('Testing...')
with open( './data.txt', mode='r') as data:
    for line in data:
        print line


print ('Test Over')
