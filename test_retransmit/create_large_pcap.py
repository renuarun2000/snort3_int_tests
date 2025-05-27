#!/usr/bin/env python3
from scapy.all import *
import os
import random

# Create a 5MB file with MALWARE signature at the beginning
def create_large_file(filename, size_mb=5):
    size_bytes = size_mb * 1024 * 1024
    
    print(f"Creating {size_mb}MB file: {filename}")
    with open(filename, 'wb') as f:
        # Write the MALWARE signature at the beginning
        f.write(b"MALWARE")
        
        # Fill the rest with random data
        remaining_bytes = size_bytes - 7  # 7 is the length of "MALWARE"
        chunk_size = 1024 * 1024  # Write in 1MB chunks
        
        while remaining_bytes > 0:
            if remaining_bytes < chunk_size:
                chunk_size = remaining_bytes
            
            # Generate random data
            random_data = bytes([random.randint(0, 255) for _ in range(chunk_size)])
            f.write(random_data)
            remaining_bytes -= chunk_size
    
    print(f"Created {filename} ({os.path.getsize(filename)} bytes)")

# Create a PCAP file with HTTP transfer of the large file
def create_large_pcap(pcap_file, large_file):
    print(f"Creating PCAP file: {pcap_file}")
    
    # Read the large file
    with open(large_file, 'rb') as f:
        file_data = f.read()
    
    # Network parameters
    client_ip = "10.1.0.2"
    server_ip = "10.1.0.1"
    client_port = 49152
    server_port = 80
    
    # Initial sequence numbers
    client_seq = 1000
    server_seq = 2000
    
    # Create HTTP GET request
    http_get = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="PA", seq=client_seq)/Raw(
        b"GET /large_file.bin HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: Mozilla/5.0\r\n"
        b"Accept: */*\r\n"
        b"\r\n"
    )
    
    # Calculate the length of the GET request payload
    get_len = len(http_get[Raw])
    
    # Create HTTP response header
    http_resp_header = Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA", seq=server_seq)/Raw(
        b"HTTP/1.1 200 OK\r\n"
        b"Server: Apache\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Length: " + str(len(file_data)).encode() + b"\r\n"
        b"\r\n"
    )
    
    # Calculate the length of the response header
    resp_header_len = len(http_resp_header[Raw])
    
    # Client ACK for the response header
    client_ack1 = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="A", seq=client_seq+get_len, ack=server_seq+resp_header_len)
    
    # Create packets for the file data
    packets = [http_get, http_resp_header, client_ack1]
    
    # Split the file data into multiple TCP segments
    segment_size = 1460  # Standard MSS
    file_offset = 0
    current_seq = server_seq + resp_header_len
    
    while file_offset < len(file_data):
        # Determine the size of this segment
        if file_offset + segment_size > len(file_data):
            segment_data = file_data[file_offset:]
        else:
            segment_data = file_data[file_offset:file_offset+segment_size]
        
        # Create a packet with this segment
        file_pkt = Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="PA", seq=current_seq)/Raw(segment_data)
        packets.append(file_pkt)
        
        # Create client ACK for this segment
        client_ack = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="A", seq=client_seq+get_len, ack=current_seq+len(segment_data))
        packets.append(client_ack)
        
        # Update for next segment
        file_offset += len(segment_data)
        current_seq += len(segment_data)
        
        # Print progress
        if file_offset % (1024 * 1024) == 0:
            print(f"  Created packets for {file_offset / (1024 * 1024):.1f}MB of data")
    
    # Final FIN packet from server
    fin_pkt = Ether()/IP(src=server_ip, dst=client_ip)/TCP(sport=server_port, dport=client_port, flags="FA", seq=current_seq)
    packets.append(fin_pkt)
    
    # Final ACK from client
    final_ack = Ether()/IP(src=client_ip, dst=server_ip)/TCP(sport=client_port, dport=server_port, flags="A", seq=client_seq+get_len, ack=current_seq+1)
    packets.append(final_ack)
    
    # Write packets to PCAP file
    wrpcap(pcap_file, packets)
    print(f"Created {pcap_file} with {len(packets)} packets")

# Create a test script to run Snort with the large PCAP
def create_test_script():
    script = """#!/bin/bash

# Create a simplified file_magic.rules
cat > file_magic.rules << EOF
# Simple file_magic.rules for testing
file_id (msg:"Test File"; file_meta:type TEST_FILE, id 1, category "Test Files"; file_data; content:"MALWARE", depth 7, offset 0; gid:4; sid:1000; rev:1;)
EOF

# Create a test configuration
cat > large_file_test.lua << EOF
-- Basic network settings
HOME_NET = "10.1.0.0/16"
EXTERNAL_NET = "any"

-- Include default configurations
dofile('snort_defaults.lua')

-- Stream configuration
stream = { }
stream_tcp = { 
    show_rebuilt_packets = true,
    session_timeout = 180,
    flush_factor = 0
}

-- HTTP Inspector
http_inspect = { }

-- File ID configuration
file_id = {
    type_depth = 1460,        -- One full TCP segment
    enable_type = true,
    enable_signature = true,
    enable_capture = true,
    trace_type = true,
    rules_file = 'file_magic.rules'
}

-- File policy configuration
file_policy = {
    enable_type = true,
    enable_signature = true,
    enable_capture = true,
    verdict_delay = 0,
    rules = {
        {
            when = { file_type_id = 1 },
            use = { verdict = "log" }
        }
    }
}

-- Wizard for protocol identification
wizard = default_wizard

-- Trace options for debugging
trace = {
    modules = {
        file_api = { all = 3 },
        stream_tcp = { all = 2 }
    }
}
EOF

# Run Snort with this configuration
echo "Running Snort with large file test configuration..."
snort -c large_file_test.lua -r large_file.pcap -A alert_fast -k none -Q -v > large_file.log 2>&1

# Check if file type was detected
echo -e "\\nFile type detection results:"
echo "============================"
grep "File type:" large_file.log || echo "No file type detection"

# Check which packet had the detection
packet_num=$(grep -B 5 "File type:" large_file.log | grep "Processing packet" | tail -1 | awk '{print $3}')
if [ -n "$packet_num" ]; then
    echo "File type detected in packet $packet_num"
    
    # Get total number of packets
    total_packets=$(grep "Processing packet" large_file.log | wc -l)
    echo "Total packets: $total_packets"
    
    # Calculate percentage of file processed before detection
    percentage=$(echo "scale=2; $packet_num * 100 / $total_packets" | bc)
    echo "File type detected after processing $percentage% of packets"
else
    echo "Could not determine packet number for file type detection"
fi

echo -e "\\nFull log is available in large_file.log"
"""
    
    with open("test_large_file.sh", "w") as f:
        f.write(script)
    
    os.chmod("test_large_file.sh", 0o755)
    print("Created test_large_file.sh script")

# Main function
def main():
    large_file = "large_file.bin"
    pcap_file = "large_file.pcap"
    
    # Create the large file
    create_large_file(large_file)
    
    # Create the PCAP file
    create_large_pcap(pcap_file, large_file)
    
    # Create the test script
    create_test_script()
    
    print("\nSetup complete. Run the test with:")
    print("  ./test_large_file.sh")

if __name__ == "__main__":
    main()