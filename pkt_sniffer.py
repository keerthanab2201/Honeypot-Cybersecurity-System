"""  #basic implementation 
import socket #built-in module to create and manage sockets

#create a raw socket to capture TCP packets
raw_socket= socket.socket(socket.AF_INET, socket.SOCKRAW, socket.IPPROTO_TCP)
'''socket.AF_INET →  IPv4 addresses.
   socket.SOCK_RAW → creates a raw socket (can see all packet details).
   socket.IPPROTO_TCP → to capture only TCP packets.'''

#bind to all interfaces(0.0.0.0)
raw_socket.bind(("0.0.0.0", 0))
''' 0.0.0.0 -> Listen on all network interfaces
    0 -> not binding to a specific port".
    Binding connects the socket to computer’s network interface so it can start receiving data '''

#enable capturing of the full packet, including headers
raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

print("Honeypot is running... Listening for incoming packets.")

while True:
    packet, addr = raw_socket.recvfrom(65535)  # Receive packets
    print(f"Captured Packet from {addr}: {packet[:50]}")  # Show first 50 bytes

''' recvfrom(65535) -> tells the socket to receive up to 65,535 bytes (the max size of a network packet)
    addr -> source IP address of the sender.
    packet -> contains raw data of the packet.
    packet[:50] -> shows the first 50 bytes for readability. '''
"""

import socket
import struct

def parse_ip_header(data):
    ip_header = struct.unpack("!BBHHHBBH4s4s", data[:20])
    version_ihl = ip_header[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    total_length = ip_header[2]
    protocol = ip_header[6]
    src_ip = socket.inet_ntoa(ip_header[8])
    dst_ip = socket.inet_ntoa(ip_header[9])
    return {
        'version': version,
        'ihl': ihl,
        'total_length': total_length,
        'protocol': protocol,
        'src_ip': src_ip,
        'dst_ip': dst_ip
    }

def parse_tcp_header(data):
    tcp_header = struct.unpack('!HHLLBBHHH', data[:20])
    src_port = tcp_header[0]
    dst_port = tcp_header[1]
    seq = tcp_header[2]
    ack = tcp_header[3]
    offset_reserved = tcp_header[4]
    flags = tcp_header[5]
    flag_bits = {
        "URG": (flags & 32) >> 5,
        "ACK": (flags & 16) >> 4,
        "PSH": (flags & 8) >> 3,
        "RST": (flags & 4) >> 2,
        "SYN": (flags & 2) >> 1,
        "FIN": flags & 1
    }
    return {
        'src_port': src_port,
        'dst_port': dst_port,
        'flags': flag_bits
    }

# Create raw socket
raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
raw_socket.bind(("0.0.0.0", 0))
raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

print("🕵️ Honeypot running... Listening and parsing packets...\n")

while True:
    packet, addr = raw_socket.recvfrom(65535)

    # Parse IP Header
    ip_info = parse_ip_header(packet[:20])

    # Calculate where the TCP header starts
    ip_header_length = ip_info['ihl'] * 4
    tcp_info = parse_tcp_header(packet[ip_header_length:ip_header_length+20])

    print(f"📦 Packet Received:")
    print(f"   From IP     : {ip_info['src_ip']}:{tcp_info['src_port']}")
    print(f"   To IP       : {ip_info['dst_ip']}:{tcp_info['dst_port']}")
    print(f"   Flags       : {', '.join([k for k, v in tcp_info['flags'].items() if v])}")
    print(f"   Packet Size : {ip_info['total_length']} bytes\n")
