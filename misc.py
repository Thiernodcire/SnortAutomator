#!/usr/bin/env python3
import pyshark as py
import sys
src_dictionary = {}
dst_dictionary = {}
snort_rule_list = []

def main():
    pcap_capture()

def pcap_capture():
    good_ip = ['10.42.0.91']
    cap = py.FileCapture(sys.argv[1])
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
    compare_traffic(good_ip)
def compare_traffic(whitelist_ip):
    src_dictionary_list = list(src_dictionary.keys())
    dst_dictionnary_list = list(dst_dictionary.keys())
    for idx, ip in enumerate(src_dictionary_list):
        if ip not in whitelist_ip:
            snort_rule = 'alert tcp {bad_src_ip} {bad_src_port} -> {bad_dst_ip} {bad_dst_port}'
            snort_rule_list.append(snort_rule.format(bad_src_ip=ip,bad_src_port=src_dictionary[ip],bad_dst_ip=dst_dictionnary_list[idx],bad_dst_port=dst_dictionary[dst_dictionnary_list[idx]]))
    rule_generator(snort_rule_list)
def rule_generator(rules):
    print('Here, are your rules')
    for rules in snort_rule_list:
        print(rules)
if __name__ == "__main__":
    main()