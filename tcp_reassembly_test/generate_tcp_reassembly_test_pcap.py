#!/usr/bin/env python3
"""
Generate a PCAP file with TCP packets designed to test Snort's TCP reassembly
with partial flush, retransmissions, and out-of-order packets.
"""

from scapy.all import *
import random
import time

def create_tcp_reassembly_test_pcap(filename="tcp_reassembly_test.pcap"):
    """Create a PCAP file with TCP packets to test reassembly issues."""
    
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
    
    # 1. TCP 3-way handshake
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
    
    # 2. HTTP Request (split into multiple segments to trigger reassembly)
    http_req_part1 = Ether()/IP(src=client_ip, dst=server_ip)/TCP(
        sport=client_port, dport=server_port, flags="PA", 
        seq=client_seq+1, ack=server_seq+1,
        options=[('NOP', None), ('NOP', None), 
                 ('Timestamp', (400, 200))]
    )/Raw(load="GET /index.html HTTP/1.1\r\nHost: example.com\r\n")
    packets.append(http_req_part1)
    
    # Server ACK for part 1
    server_ack1 = Ether()/IP(src=server_ip, dst=client_ip)/TCP(
        sport=server_port, dport=client_port, flags="A", 
        seq=server_seq+1, ack=client_seq+1+len(http_req_part1[Raw]),
        options=[('NOP', None), ('NOP', None), 
                 ('Timestamp', (500, 400))]
    )
    packets.append(server_ack1)
    
    # HTTP Request part 2
    http_req_part2 = Ether()/IP(src=client_ip, dst=server_ip)/TCP(
        sport=client_port, dport=server_port, flags="PA", 
        seq=client_seq+1+len(http_req_part1[Raw]), ack=server_seq+1,
        options=[('NOP', None), ('NOP', None), 
                 ('Timestamp', (600, 500))]
    )/Raw(load="Content-Length: 0\r\n\r\n")
    packets.append(http_req_part2)
    
    # Server ACK for part 2
    server_ack2 = Ether()/IP(src=server_ip, dst=client_ip)/TCP(
        sport=server_port, dport=client_port, flags="A", 
        seq=server_seq+1, ack=client_seq+1+len(http_req_part1[Raw])+len(http_req_part2[Raw]),
        options=[('NOP', None), ('NOP', None), 
                 ('Timestamp', (700, 600))]
    )
    packets.append(server_ack2)
    
    # 3. HTTP Response (split into multiple segments with out-of-order delivery)
    # First, calculate the total response size
    http_resp_header = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 1000\r\n\r\n"
    http_resp_body = "<html><body>" + "X" * 980 + "</body></html>"
    
    # Send response header
    http_resp_part1 = Ether()/IP(src=server_ip, dst=client_ip)/TCP(
        sport=server_port, dport=client_port, flags="PA", 
        seq=server_seq+1, ack=client_seq+1+len(http_req_part1[Raw])+len(http_req_part2[Raw]),
        options=[('NOP', None), ('NOP', None), 
                 ('Timestamp', (800, 700))]
    )/Raw(load=http_resp_header)
    packets.append(http_resp_part1)
    
    # Client ACK for response header
    client_ack1 = Ether()/IP(src=client_ip, dst=server_ip)/TCP(
        sport=client_port, dport=server_port, flags="A", 
        seq=client_seq+1+len(http_req_part1[Raw])+len(http_req_part2[Raw]), 
        ack=server_seq+1+len(http_resp_part1[Raw]),
        options=[('NOP', None), ('NOP', None), 
                 ('Timestamp', (900, 800))]
    )
    packets.append(client_ack1)
    
    # Split response body into chunks
    chunk_size = 200
    chunks = [http_resp_body[i:i+chunk_size] for i in range(0, len(http_resp_body), chunk_size)]
    
    # Send chunks out of order: 3, 1, 4, 2, 5
    chunk_order = [2, 0, 3, 1, 4]
    
    for i, chunk_idx in enumerate(chunk_order):
        chunk = chunks[chunk_idx]
        chunk_seq = server_seq+1+len(http_resp_part1[Raw])+chunk_idx*chunk_size
        
        http_resp_chunk = Ether()/IP(src=server_ip, dst=client_ip)/TCP(
            sport=server_port, dport=client_port, flags="PA" if i == len(chunk_order)-1 else "A", 
            seq=chunk_seq, ack=client_seq+1+len(http_req_part1[Raw])+len(http_req_part2[Raw]),
            options=[('NOP', None), ('NOP', None), 
                     ('Timestamp', (1000+i*100, 900))]
        )/Raw(load=chunk)
        packets.append(http_resp_chunk)
        
        # Client ACK for each chunk
        client_ack_chunk = Ether()/IP(src=client_ip, dst=server_ip)/TCP(
            sport=client_port, dport=server_port, flags="A", 
            seq=client_seq+1+len(http_req_part1[Raw])+len(http_req_part2[Raw]), 
            ack=chunk_seq+len(chunk),
            options=[('NOP', None), ('NOP', None), 
                     ('Timestamp', (1100+i*100, 1000+i*100))]
        )
        packets.append(client_ack_chunk)
    
    # 4. Retransmit a packet that should trigger partial flush
    # Retransmit chunk 1 (which was sent as the second chunk)
    retrans_chunk = chunks[0]
    retrans_seq = server_seq+1+len(http_resp_part1[Raw])
    
    http_resp_retrans = Ether()/IP(src=server_ip, dst=client_ip)/TCP(
        sport=server_port, dport=client_port, flags="A", 
        seq=retrans_seq, ack=client_seq+1+len(http_req_part1[Raw])+len(http_req_part2[Raw]),
        options=[('NOP', None), ('NOP', None), 
                 ('Timestamp', (1600, 1500))]
    )/Raw(load=retrans_chunk)
    packets.append(http_resp_retrans)
    
    # 5. Send a packet with sequence number less than the retransmitted packet
    # This packet should be dropped if the issue exists
    small_seq_packet = Ether()/IP(src=server_ip, dst=client_ip)/TCP(
        sport=server_port, dport=client_port, flags="A", 
        seq=retrans_seq-50, ack=client_seq+1+len(http_req_part1[Raw])+len(http_req_part2[Raw]),
        options=[('NOP', None), ('NOP', None), 
                 ('Timestamp', (1700, 1600))]
    )/Raw(load="This packet has a sequence number less than the retransmitted packet")
    packets.append(small_seq_packet)
    
    # 6. Send a normal packet after the problematic ones
    normal_packet = Ether()/IP(src=server_ip, dst=client_ip)/TCP(
        sport=server_port, dport=client_port, flags="PA", 
        seq=server_seq+1+len(http_resp_part1[Raw])+len(http_resp_body), 
        ack=client_seq+1+len(http_req_part1[Raw])+len(http_req_part2[Raw]),
        options=[('NOP', None), ('NOP', None), 
                 ('Timestamp', (1800, 1700))]
    )/Raw(load="This is a normal packet after the problematic sequence")
    packets.append(normal_packet)
    
    # Client ACK for the normal packet
    client_ack_final = Ether()/IP(src=client_ip, dst=server_ip)/TCP(
        sport=client_port, dport=server_port, flags="A", 
        seq=client_seq+1+len(http_req_part1[Raw])+len(http_req_part2[Raw]), 
        ack=server_seq+1+len(http_resp_part1[Raw])+len(http_resp_body)+len(normal_packet[Raw]),
        options=[('NOP', None), ('NOP', None), 
                 ('Timestamp', (1900, 1800))]
    )
    packets.append(client_ack_final)
    
    # 7. Connection teardown
    # FIN from client
    fin = Ether()/IP(src=client_ip, dst=server_ip)/TCP(
        sport=client_port, dport=server_port, flags="FA", 
        seq=client_seq+1+len(http_req_part1[Raw])+len(http_req_part2[Raw]), 
        ack=server_seq+1+len(http_resp_part1[Raw])+len(http_resp_body)+len(normal_packet[Raw]),
        options=[('NOP', None), ('NOP', None), 
                 ('Timestamp', (2000, 1900))]
    )
    packets.append(fin)
    
    # FIN-ACK from server
    fin_ack = Ether()/IP(src=server_ip, dst=client_ip)/TCP(
        sport=server_port, dport=client_port, flags="FA", 
        seq=server_seq+1+len(http_resp_part1[Raw])+len(http_resp_body)+len(normal_packet[Raw]), 
        ack=client_seq+2+len(http_req_part1[Raw])+len(http_req_part2[Raw]),
        options=[('NOP', None), ('NOP', None), 
                 ('Timestamp', (2100, 2000))]
    )
    packets.append(fin_ack)
    
    # ACK from client
    last_ack = Ether()/IP(src=client_ip, dst=server_ip)/TCP(
        sport=client_port, dport=server_port, flags="A", 
        seq=client_seq+2+len(http_req_part1[Raw])+len(http_req_part2[Raw]), 
        ack=server_seq+2+len(http_resp_part1[Raw])+len(http_resp_body)+len(normal_packet[Raw]),
        options=[('NOP', None), ('NOP', None), 
                 ('Timestamp', (2200, 2100))]
    )
    packets.append(last_ack)
    
    # Write packets to PCAP file
    wrpcap(filename, packets)
    print(f"Created PCAP file: {filename}")
    print(f"Key packets to observe:")
    print(f"- Packets #{len(packets)-3}, #{len(packets)-2}: Retransmitted packet and packet with smaller sequence")
    print(f"- If the issue exists, packet #{len(packets)-2} (small_seq_packet) will be dropped by Snort")

if __name__ == "__main__":
    create_tcp_reassembly_test_pcap()