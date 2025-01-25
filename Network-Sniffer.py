import socket
import struct
import textwrap
from scapy.all import *

# Unpack Ethernet Frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Format MAC Address
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

# Unpack IPv4 Packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# Format IPv4 Address
def ipv4(addr):
    return '.'.join(map(str, addr))

# Unpack TCP Segment
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# Unpack UDP Segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

# Format Multi-line Data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ' '.join(f'{byte:02x}' for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([f"{prefix}{line}" for line in textwrap.wrap(string, size)])

# Main Sniffer Function
def main():
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

    # Enable promiscuous mode (platform-dependent)
    conn.bind(("0.0.0.0", 0))
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print(f'\tDestination MAC Address: {dest_mac}, Source MAC Address: {src_mac}, Protocol: {eth_proto}')

        # IPv4
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print(f'\tIPv4 Packet:')
            print(f'\t\tVersion: {version}, Header Length: {header_length}, TTL: {ttl}')
            print(f'\t\tProtocol: {proto}, Source: {src}, Target: {target}')

            # TCP
            if proto == 6:
                (src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
                print(f'\t\tTCP Segment:')
                print(f'\t\t\tSource Port: {src_port}, Destination Port: {dest_port}')
                print(f'\t\t\tSequence: {sequence}, Acknowledgment: {acknowledgment}')
                print(f'\t\t\tFlags:')
                print(f'\t\t\t\tURG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}, RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}')
                formatted_data = format_multi_line("\t\t\t\t", data)
                print(f'\t\t\tData: {formatted_data}')

            # UDP
            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print(f'\t\tUDP Segment:')
                print(f'\t\t\tSource Port: {src_port}, Destination Port: {dest_port}, Length: {length}')

            # Other Protocols
            else:
                formatted_data = format_multi_line("\t\t", data)
                print(f'\t\tOther Protocol: Data: {formatted_data}')

if __name__ == "__main__":
    main()
