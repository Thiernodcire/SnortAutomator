#!/usr/bin/env python3 
import pyshark
import csv
count=0
cap = pyshark.FileCapture('/Users/tharwatkaasem/Documents/Imrsv/FP/network.pcap')
with open('traffic2.csv', 'w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["SN","ip.src", "port.src", "ip.dst", "port.dst", "sniff.time", "timestamp", "flag"])
    for pack in cap:
        try:
            writer.writerow([count, pack.ip.src , pack.tcp.srcport , pack.ip.dst , pack.tcp.dstport , pack.sniff_time , pack.sniff_timestamp , pack.tcp.flags] )
            print("------------------------------------")     
            print (pack.ip.src)
            print (pack.ip.dst)
            print (pack.tcp.srcport)
            print (pack.tcp.dstport)
            print (pack.sniff_timestamp)
            print (pack.sniff_time)
            print (pack.tcp.flags)

#           print (pack.udp.srcport)
#           print (pack.udp.dstport)
            print("------------------------------------")

        except:
            print("NONE TCP/UDP")
        
        count= count+1


#print (cap[3].ip.src)
#print (cap[3].ip.dst)
#print (cap[3].tcp.srcport)
#print (cap[3].tcp.dstport)
#print (cap[3].tcp.flags)
#print (cap[3].sniff_timestamp)
#print (cap[3].sniff_time)

#print (cap[3])