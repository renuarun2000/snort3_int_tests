#!/bin/bash

# Check if the large file PCAP exists
if [ ! -f "large_file.pcap" ]; then
    echo "Creating large file and PCAP..."
    python3 create_large_pcap.py
fi

# Create a simplified file_magic.rules
cat > file_magic.rules << EOF
# Simple file_magic.rules for testing
file_id (msg:"Test File"; file_meta:type TEST_FILE, id 1, category "Test Files"; file_data; content:"MALWARE", depth 7, offset 0; gid:4; sid:1000; rev:1;)
EOF

# Test with different file_type_depth values
for depth in 8 64 128 256 512 1024 1460 2920; do
    echo -e "\nTesting with file_type_depth = $depth"
    echo "=================================="
    
    # Create a test configuration
    cat > large_depth_${depth}.lua << EOF
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

-- File ID configuration with specific depth
file_id = {
    type_depth = ${depth},        -- Test different depths
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
    echo "Running Snort with depth = $depth..."
    snort -c large_depth_${depth}.lua -r large_file.pcap -A alert_fast -k none -Q -v > large_depth_${depth}.log 2>&1
    
    # Check if file type was detected
    echo "File type detection results:"
    grep "File type:" large_depth_${depth}.log || echo "No file type detection"
    
    # Check which packet had the detection
    packet_num=$(grep -B 5 "File type:" large_depth_${depth}.log | grep "Processing packet" | tail -1 | awk '{print $3}')
    if [ -n "$packet_num" ]; then
        echo "File type detected in packet $packet_num"
        
        # Get total number of packets
        total_packets=$(grep "Processing packet" large_depth_${depth}.log | wc -l)
        echo "Total packets: $total_packets"
        
        # Calculate percentage of file processed before detection
        percentage=$(echo "scale=2; $packet_num * 100 / $total_packets" | bc)
        echo "File type detected after processing $percentage% of packets"
    else
        echo "Could not determine packet number for file type detection"
    fi
done

# Create a summary
echo -e "\nSummary of File Type Detection by Depth:"
echo "======================================="
for depth in 8 64 128 256 512 1024 1460 2920; do
    packet_num=$(grep -B 5 "File type:" large_depth_${depth}.log | grep "Processing packet" | tail -1 | awk '{print $3}')
    if [ -n "$packet_num" ]; then
        total_packets=$(grep "Processing packet" large_depth_${depth}.log | wc -l)
        percentage=$(echo "scale=2; $packet_num * 100 / $total_packets" | bc)
        echo "Depth $depth: File type detected in packet $packet_num ($percentage% of packets)"
    else
        echo "Depth $depth: No file type detection"
    fi
done