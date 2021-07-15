#!/usr/bin/env python3 
import pyshark
import csv
import pandas
count=0
cap = pyshark.FileCapture('/Users/tharwatkaasem/Documents/Imrsv/FP/nmap-scan.pcap')
with open('traffic.csv', 'w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["SN","ipsrc", "portsrc", "ipdst", "portdst", "snifftime", "timestamp", "flag"])
    for pack in cap:
        try:
            writer.writerow([count, pack.ip.src , pack.tcp.srcport , pack.ip.dst , pack.tcp.dstport , pack.sniff_time , pack.sniff_timestamp , pack.tcp.flags] )
                #print("------------------------------------")     
                #print (pack.ip.src)
                #print (pack.ip.dst)
                #print (pack.tcp.srcport)
                #print (pack.tcp.dstport)
                #print (pack.sniff_timestamp)
                #print (pack.sniff_time)
                #print (pack.tcp.flags)

#               print (pack.udp.srcport)
#               print (pack.udp.dstport)
                #print("------------------------------------")

        except:
             print("NONE TCP/UDP")

        count= count+1

#print ("-------------------------------------------")
#print ("-------------------------------------------")
#print ("-------------------------------------------")
#Create white list of IP's
whitelist = open("IP_whitelist", "r")
wl=whitelist.read()
#Check for unique IP's in traffic
uip= pandas.read_csv("traffic.csv") 
unip=uip.ipsrc.unique()
unport=uip.portdst.unique()
#count number of packets for each uniqe ipsrc
ipuncount=uip['ipsrc'].value_counts().reset_index(name='portdst')
portcount=uip['portdst'].value_counts()
flags= uip['flag'].unique()
#print (ipuncount)
#print (flags)
#print(portcount)

for ipsrc in unip:
    if ipsrc not in wl:
        #print (ipsrc)
        syn_flag= uip[(uip.ipsrc == ipsrc) & (uip.flag == '0x00000002')]
        num_scanned_ports= len(syn_flag)
        #print (num_scanned_ports) 
        if len(syn_flag) >= 100:
            print ("\n\n\n")
            print ("----------------------------------------------------------------------------------")
            print (f"{ipsrc} scanned {num_scanned_ports} ports on your network... This is a high indicator of active Nmap scan\n")
            print (f"Consider applying the following firewall rule: <ufw deny from {ipsrc}>")
            print ("----------------------------------------------------------------------------------")
            print ("\n\n\n")
        else:
            print (f"No port scan detected on your network from {ipsrc}...")

