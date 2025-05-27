#!/usr/bin/env python3

from scapy.all import *
import random

# IP addresses and ports
client_ip = "10.1.1.10"
server_ip = "10.1.2.20"
client_port = 12345
server_port = 80

# Create a PCAP file
pcap_file = "retransmit_test.pcap"

# Initialize sequence numbers
client_seq = random.randint(1000000, 9000000)
server_seq = random.randint(1000000, 9000000)

# TCP handshake
syn = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="S", seq=client_seq)
syn_ack = Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="SA", seq=server_seq, ack=client_seq+1)
ack = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="A", seq=client_seq+1, ack=server_seq+1)

# HTTP GET request
http_get = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA", seq=client_seq+1, ack=server_seq+1)/Raw(load="GET /file.bin HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n")

# Server ACK for the request
server_ack = Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="A", seq=server_seq+1, ack=client_seq+1+len(http_get[Raw]))

# HTTP response with file content
http_resp_header = Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA", seq=server_seq+1, ack=client_seq+1+len(http_get[Raw]))/Raw(load="HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 100\r\n\r\n")

# Client ACK for the header
ack_header = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="A", seq=client_seq+1+len(http_get[Raw]), ack=server_seq+1+len(http_resp_header[Raw]))

# First part of file content - this will be held for inspection
file_part1 = Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA", seq=server_seq+1+len(http_resp_header[Raw]), ack=client_seq+1+len(http_get[Raw]))/Raw(load="MALWARE-content-part1")

# Retransmission of the first part - this should be processed while the original is held
file_part1_retransmit = Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA", seq=server_seq+1+len(http_resp_header[Raw]), ack=client_seq+1+len(http_get[Raw]))/Raw(load="MALWARE-content-part1")

# Second part of file content
file_part2 = Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA", seq=server_seq+1+len(http_resp_header[Raw])+len(file_part1[Raw]), ack=client_seq+1+len(http_get[Raw]))/Raw(load="-content-part2-end")

# ACK from client for the first part of file
ack_part1 = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="A", seq=client_seq+1+len(http_get[Raw]), ack=server_seq+1+len(http_resp_header[Raw])+len(file_part1[Raw]))

# ACK from client for the second part of file
ack_part2 = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="A", seq=client_seq+1+len(http_get[Raw]), ack=server_seq+1+len(http_resp_header[Raw])+len(file_part1[Raw])+len(file_part2[Raw]))

# TCP connection teardown
fin_client = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="FA", seq=client_seq+1+len(http_get[Raw]), ack=server_seq+1+len(http_resp_header[Raw])+len(file_part1[Raw])+len(file_part2[Raw]))
fin_ack_server = Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="FA", seq=server_seq+1+len(http_resp_header[Raw])+len(file_part1[Raw])+len(file_part2[Raw]), ack=client_seq+2+len(http_get[Raw]))
ack_client = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="A", seq=client_seq+2+len(http_get[Raw]), ack=server_seq+2+len(http_resp_header[Raw])+len(file_part1[Raw])+len(file_part2[Raw]))

# Write packets to PCAP file
packets = [
    syn, syn_ack, ack,                  # TCP handshake
    http_get, server_ack,               # HTTP request
    http_resp_header, ack_header,       # HTTP response header
    file_part1,                         # First part of file (will be held)
    file_part1_retransmit,              # Retransmission of first part
    ack_part1,                          # ACK for first part
    file_part2, ack_part2,              # Second part of file
    fin_client, fin_ack_server, ack_client  # TCP teardown
]

# Add timestamps to packets (1 second between packets, with retransmit coming 1 second after original)
for i, pkt in enumerate(packets):
    # Add a delay before the retransmission
    if i == 7:  # file_part1
        pkt.time = i
    elif i == 8:  # file_part1_retransmit
        pkt.time = i + 1  # 1 second after the original
    else:
        pkt.time = i

# Write to PCAP
wrpcap(pcap_file, packets)
print(f"Created PCAP file: {pcap_file}")
print(f"Key packets:")
print(f"- Packet #8: Original file part with 'MALWARE' content (will be held)")
print(f"- Packet #9: Retransmission of file part (arrives during verdict delay)")
print(f"- After verdict delay, Snort will try to retry packet #8")
