#!/usr/bin/env python3 
import pyshark 
print('Hello')
capture = pyshark.LiveCapture(interface='eth0')
print(capture)
capture.sniff(timeout=20)
print(capture)
for pack in capture:
    print(pack)
    print('Hit the loop')
    try:
        ip_src = pack.ip.src
        print(ip_src)
        ip_dst = pack.ip.dst
        print(ip_dst)
        src_port = pack.tcp.srcport
        dst_port = pack.tcp.dstport
    except:
        arp_traffic = pack
        print(arp_traffic)