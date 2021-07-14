#!/usr/bin/env python3 
import pyshark as py
src_dictionary = {}
dst_dictionary = {}
snort_rule_list = []
def pcap_capture(pcap,):
    cap = py.FileCapture(pcap)
    for pack in cap:
        try:
            ip_src = pack.ip.src
            ip_dst = pack.ip.dst
            src_port = pack.tcp.srcport
            dst_port = pack.tcp.dstport
        except:
            arp_traffic = pack
        src_dictionary[ip_src] = src_port
        dst_dictionary[ip_dst] = dst_port
def live_capture(timeout_n,interface_c):
    capture = py.LiveCapture(interface=interface_c, display_filter="tcp")
    capture.sniff(timeout=timeout_n)
    for pack in capture:
        try:
            ip_src = pack.ip.src
            ip_dst = pack.ip.dst
            src_port = pack.tcp.srcport
            dst_port = pack.tcp.dstport
        except:
            arp_traffic = pack
        src_dictionary[ip_src] = src_port
        dst_dictionary[ip_dst] = dst_port
    return 'Done' 
def compare_traffic(whitelist_ip):
    if whitelist_ip != '' and whitelist_ip == '[0-9]{1,3}\.){3}[0-9]{1,3}':
        striped_whitelist_ip = whitelist_ip.strip(' ')
        for idx, ip in enumerate(src_dictionary.keys()):
            if ip not in striped_whitelist_ip:
                snort_rule = 'alert tcp {bad_src_ip} {bad_src_port} -> {bad_dst_ip} {bad_dst_port}'
                snort_rule_list.append(snort_rule.format(bad_src_ip=ip,bad_src_port=src_dictionary[ip],bad_dst_ip=dst_dictionary.keys()[idx],bad_dst_port=dst_dictionary.values()[idx]))
    rule_generator(snort_rule_list)
def rule_generator(rules):
    print('Here, are your rules')
    for rules in snort_rule_list:
        print(rules)
