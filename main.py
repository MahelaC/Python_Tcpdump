#!/usr/bin/python

import struct
import socket
import unpack
from datetime import datetime

conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

def get_mac(b_addr):
    b_str = map('{:02x}'.format, b_addr)
    return ':'.join(b_str).upper()

try:
    while True:
        raw_data = conn.recvfrom(65536)[0]
        #Ethernet Header unpacking
        unpack.eth(raw_data[:14])
        now = datetime.now()
        global c_time
        c_time = now.strftime("%H:%M:%S.%f")

        #ipv4 Header
        if unpack.eth_protocol == 2048:
            unpack.ipv4(raw_data[14:34])

            #ICMP unpacking
            if unpack.ip_proto == 1:
                unpack.icmp(raw_data[34:54])
                icmp_len = len(raw_data[34:])
                if unpack.icmp_type == 0:
                    icmp_type = 'ICMP echo reply'
                else:
                    icmp_type = 'ICMP echo request'
                print(f'{c_time}|ICMP| IP,{unpack.s_ip} > {unpack.d_ip},{unpack.icmp_type} id {unpack.icmp_id}, seq {unpack.icmp_seq}, length {icmp_len}')

            #TCP unpacking
            elif unpack.ip_proto == 6:
                unpack.tcp(raw_data[34:54])
                print(f'{c_time}|TCP| IP,{unpack.s_ip}.{unpack.t_s_port} > {unpack.d_ip}.{unpack.t_d_port}: Flags [{unpack.tcp_flag}]')       

            #UDP unpacking
            elif unpack.ip_proto == 17:
                unpack.udp(raw_data[34:42])
                udp_length = len(raw_data[34:])
                print(f'{c_time}|UDP| IP,{unpack.s_ip}.{unpack.udp_s_port} > {unpack.d_ip}.{unpack.udp_d_port}: UDP length {udp_length}')

        #ARP unpacking
        elif unpack.eth_protocol == 2054:
            arp_pak = struct.unpack('! 2s 2s 1s 1s H 6s 4s 6s 4s',raw_data[14:42])
            opcode = arp_pak[4]
            if opcode == 1:
                sender_mac = get_mac(arp_pak[5])
                sender_ip = socket.inet_ntoa(arp_pak[6])
                target_mac = get_mac(arp_pak[7])
                target_ip = socket.inet_ntoa(arp_pak[8])
                le = len(raw_data[14:])
                print(f'{c_time}|ARP| IP,{sender_ip} > {target_ip} ARP, Request who-has {target_ip} tell {sender_ip}, length {le} ')
            else :
                sender_mac = get_mac(arp_pak[5])
                sender_ip = socket.inet_ntoa(arp_pak[6])
                target_mac = get_mac(arp_pak[7])
                target_ip = socket.inet_ntoa(arp_pak[8])
                le = len(raw_data[14:])
                print(f'{c_time}|ARP| IP,{sender_ip} > {target_ip} ARP,Reply {sender_ip} is-at {sender_mac}, length {le} ')

except KeyboardInterrupt as e:
     print('\nKeyboard interrupt exception caught')

