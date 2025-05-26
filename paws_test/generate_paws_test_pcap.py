#!/usr/bin/env python3
"""
Generate a PCAP file with TCP packets having out-of-order timestamps to test
Snort's PAWS (Protection Against Wrapped Sequence numbers) validation.
"""

from scapy.all import *
import random
import time

def create_paws_test_pcap(filename="paws_test.pcap"):
    """Create a PCAP file with TCP packets having timestamp issues."""
    
    # Define IP addresses
    client_ip = "192.168.1.100"
    server_ip = "10.1.1.100"
    client_port = 49152
    server_port = 80
    
    # Initialize sequence numbers
    client_seq = random.randint(1000000, 9000000)
    server_seq = random.randint(1000000, 9000000)
    
    # Create packets list
    packets = []
    
    # 1. TCP 3-way handshake with normal timestamps
    # SYN
    syn = Ether()/IP(src=client_ip, dst=server_ip)/TCP(
        sport=client_port, dport=server_port, flags="S", seq=client_seq,
        options=[('MSS', 1460), ('NOP', None), ('NOP', None), 
                 ('Timestamp', (100, 0)), ('WScale', 7)]
    )
    packets.append(syn)
    
    # SYN-ACK
    syn_ack = Ether()/IP(src=server_ip, dst=client_ip)/TCP(
        sport=server_port, dport=client_port, flags="SA", 
        seq=server_seq, ack=client_seq+1,
        options=[('MSS', 1460), ('NOP', None), ('NOP', None), 
                 ('Timestamp', (200, 100)), ('WScale', 7)]
    )
    packets.append(syn_ack)
    
    # ACK
    ack = Ether()/IP(src=client_ip, dst=server_ip)/TCP(
        sport=client_port, dport=server_port, flags="A", 
        seq=client_seq+1, ack=server_seq+1,
        options=[('NOP', None), ('NOP', None), 
                 ('Timestamp', (300, 200))]
    )
    packets.append(ack)
    
    # 2. Normal data exchange with increasing timestamps
    # Client -> Server (HTTP GET)
    http_get = Ether()/IP(src=client_ip, dst=server_ip)/TCP(
        sport=client_port, dport=server_port, flags="PA", 
        seq=client_seq+1, ack=server_seq+1,
        options=[('NOP', None), ('NOP', None), 
                 ('Timestamp', (400, 200))]
    )/Raw(load="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    packets.append(http_get)
    
    # Server -> Client (ACK)
    server_ack = Ether()/IP(src=server_ip, dst=client_ip)/TCP(
        sport=server_port, dport=client_port, flags="A", 
        seq=server_seq+1, ack=client_seq+1+len(http_get[Raw]),
        options=[('NOP', None), ('NOP', None), 
                 ('Timestamp', (500, 400))]
    )
    packets.append(server_ack)
    
    # Server -> Client (HTTP Response)
    http_resp = Ether()/IP(src=server_ip, dst=client_ip)/TCP(
        sport=server_port, dport=client_port, flags="PA", 
        seq=server_seq+1, ack=client_seq+1+len(http_get[Raw]),
        options=[('NOP', None), ('NOP', None), 
                 ('Timestamp', (600, 400))]
    )/Raw(load="HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, World!")
    packets.append(http_resp)
    
    # Client -> Server (ACK)
    client_ack = Ether()/IP(src=client_ip, dst=server_ip)/TCP(
        sport=client_port, dport=server_port, flags="A", 
        seq=client_seq+1+len(http_get[Raw]), ack=server_seq+1+len(http_resp[Raw]),
        options=[('NOP', None), ('NOP', None), 
                 ('Timestamp', (700, 600))]
    )
    packets.append(client_ack)
    
    # 3. PAWS violation: Client sends packet with timestamp in the past
    paws_violation = Ether()/IP(src=client_ip, dst=server_ip)/TCP(
        sport=client_port, dport=server_port, flags="PA", 
        seq=client_seq+1+len(http_get[Raw]), ack=server_seq+1+len(http_resp[Raw]),
        options=[('NOP', None), ('NOP', None), 
                 ('Timestamp', (350, 600))]  # Timestamp older than previous packet
    )/Raw(load="Additional data with old timestamp")
    packets.append(paws_violation)
    
    # 4. Normal packet after PAWS violation
    normal_after_paws = Ether()/IP(src=client_ip, dst=server_ip)/TCP(
        sport=client_port, dport=server_port, flags="PA", 
        seq=client_seq+1+len(http_get[Raw])+len(paws_violation[Raw]), 
        ack=server_seq+1+len(http_resp[Raw]),
        options=[('NOP', None), ('NOP', None), 
                 ('Timestamp', (800, 600))]
    )/Raw(load="Normal packet after PAWS violation")
    packets.append(normal_after_paws)
    
    # 5. Connection teardown
    # FIN from client
    fin = Ether()/IP(src=client_ip, dst=server_ip)/TCP(
        sport=client_port, dport=server_port, flags="FA", 
        seq=client_seq+1+len(http_get[Raw])+len(paws_violation[Raw])+len(normal_after_paws[Raw]), 
        ack=server_seq+1+len(http_resp[Raw]),
        options=[('NOP', None), ('NOP', None), 
                 ('Timestamp', (900, 600))]
    )
    packets.append(fin)
    
    # FIN-ACK from server
    fin_ack = Ether()/IP(src=server_ip, dst=client_ip)/TCP(
        sport=server_port, dport=client_port, flags="FA", 
        seq=server_seq+1+len(http_resp[Raw]), 
        ack=client_seq+2+len(http_get[Raw])+len(paws_violation[Raw])+len(normal_after_paws[Raw]),
        options=[('NOP', None), ('NOP', None), 
                 ('Timestamp', (1000, 900))]
    )
    packets.append(fin_ack)
    
    # ACK from client
    last_ack = Ether()/IP(src=client_ip, dst=server_ip)/TCP(
        sport=client_port, dport=server_port, flags="A", 
        seq=client_seq+2+len(http_get[Raw])+len(paws_violation[Raw])+len(normal_after_paws[Raw]), 
        ack=server_seq+2+len(http_resp[Raw]),
        options=[('NOP', None), ('NOP', None), 
                 ('Timestamp', (1100, 1000))]
    )
    packets.append(last_ack)
    
    # Write packets to PCAP file
    wrpcap(filename, packets)
    print(f"Created PCAP file: {filename}")
    print(f"PAWS violation packet is packet #{packets.index(paws_violation)+1}")

if __name__ == "__main__":
    create_paws_test_pcap()