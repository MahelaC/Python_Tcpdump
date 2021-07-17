import struct
import socket

def eth(packet):
    eth =struct.unpack("!6s6sH",packet)
    dst_mac= eth[0]
    src_mac= eth[1]
    global eth_protocol
    eth_protocol=eth[2]

def ipv4(packet):
    ipv4=struct.unpack('!BBHHHBBH4s4s', packet)
    version = ipv4[0]
    ihl = ipv4[1]
    tos = ipv4[2]
    len = ipv4[3]
    id = ipv4[4]
    ttl = ipv4[5]
    global ip_proto
    ip_proto = ipv4[6]
    checksum = ipv4[7]
    global s_ip , d_ip
    s_ip = socket.inet_ntoa(ipv4[8])
    d_ip = socket.inet_ntoa(ipv4[9])


def icmp(packet):
    icmp_pak=struct.unpack('! B B H H H B B H 4s 4s ', packet)
    global icmp_type
    icmp_type = icmp_pak[0]
    code = icmp_pak[1]
    checksum = icmp_pak[2]
    global icmp_id , icmp_seq
    icmp_id = icmp_pak[3]
    icmp_seq = icmp_pak[4]


def udp(packet):
    udp=struct.unpack('! H H H H', packet)
    global udp_s_port , udp_d_port
    udp_s_port = udp[0]
    udp_d_port = udp[1]
    checksum = udp[3]

def tcp(packet):
    tcppak=struct.unpack('! H H L L B B H H H ',packet)
    global t_s_port , t_d_port , tcp_flag
    t_s_port = tcppak[0] 
    t_d_port  = tcppak[1]
    sq_number  = tcppak[2]
    ack_number  = tcppak[3]
    offset  = tcppak[4]
    tcp_flag  = tcppak[5]
    window  = tcppak[6]
    checksum  = tcppak[7]
    urgent_pointer = tcppak[8]

def arp(packet):
    arp=struct.unpack('! 2s 2s 1s 1s H 6s 4s 6s 4s', packet)
    hardware_type = arp[0]
    protocol_type = arp[1]
    hardware_size = arp[2]
    protocol_size = arp[3]
    opcode = arp[4]
    sender_IP = socket.inet_ntoa(arp[5])
    sender_MAC = arp[6]
    target_IP = socket.inet_ntoa(arp[7])
    target_MAC = arp[8]

    
