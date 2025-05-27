from scapy.all import *
import os

# IP addresses and ports
client_ip = "10.1.0.2"
server_ip = "10.1.0.1"
client_port = 12345
server_port = 80

# Initial sequence numbers
client_seq = 1000
server_seq = 2000

# Create test files with different sizes
sizes = [5, 10, 20, 50, 100]

for size in sizes:
    # HTTP GET request
    http_get = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA", seq=client_seq, ack=server_seq)/Raw(load="GET /malware.bin HTTP/1.1\r\nHost: example.com\r\n\r\n")
    
    # HTTP 200 OK response header
    http_resp_header = Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA", seq=server_seq, ack=client_seq+len(http_get[Raw]))/Raw(load=f"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {size}\r\n\r\n")
    
    # Client ACK for the response header
    client_ack1 = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="A", seq=client_seq+len(http_get[Raw]), ack=server_seq+len(http_resp_header[Raw]))
    
    # File content with MALWARE at the beginning and padded to the specified size
    file_content = "MALWARE" + "X" * (size - 7) if size > 7 else "MALWARE"[:size]
    file_pkt = Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA", seq=server_seq+len(http_resp_header[Raw]), ack=client_seq+len(http_get[Raw]))/Raw(load=file_content)
    
    # Client ACK for the file content
    client_ack2 = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="A", seq=client_seq+len(http_get[Raw]), ack=server_seq+len(http_resp_header[Raw])+len(file_pkt[Raw]))
    
    # Write packets to PCAP file
    packets = [http_get, http_resp_header, client_ack1, file_pkt, client_ack2]
    pcap_file = f"size_{size}.pcap"
    wrpcap(pcap_file, packets)
    print(f"Created {pcap_file} with file size {size}")

# Create a shell script to test all sizes
with open("test_sizes.sh", "w") as f:
    f.write("#!/bin/bash\n\n")
    f.write("# Test with different file sizes\n")
    
    for size in sizes:
        f.write(f"\necho -e \"\\nTesting with file size = {size}\"\n")
        f.write(f"echo \"=================================\"\n")
        f.write(f"snort -c snort.lua -r size_{size}.pcap -A alert_fast -k none -Q -v > size_{size}.log 2>&1\n")
        f.write(f"echo \"File type detection results:\"\n")
        f.write(f"grep \"File type:\" size_{size}.log || echo \"No file type detection\"\n")
        f.write(f"packet_num=$(grep -B 5 \"File type:\" size_{size}.log | grep \"Processing packet\" | tail -1 | awk '{{print $3}}')\n")
        f.write(f"if [ -n \"$packet_num\" ]; then\n")
        f.write(f"    echo \"File type detected in packet $packet_num\"\n")
        f.write(f"else\n")
        f.write(f"    echo \"Could not determine packet number for file type detection\"\n")
        f.write(f"fi\n")
    
    f.write("\n# Create a summary\n")
    f.write("echo -e \"\\nSummary of File Type Detection by Size:\"\n")
    f.write("echo \"=======================================\"\n")
    
    for size in sizes:
        f.write(f"packet_num=$(grep -B 5 \"File type:\" size_{size}.log | grep \"Processing packet\" | tail -1 | awk '{{print $3}}')\n")
        f.write(f"if [ -n \"$packet_num\" ]; then\n")
        f.write(f"    echo \"Size {size}: File type detected in packet $packet_num\"\n")
        f.write(f"else\n")
        f.write(f"    echo \"Size {size}: No file type detection\"\n")
        f.write(f"fi\n")

os.chmod("test_sizes.sh", 0o755)
print("Created test_sizes.sh script")