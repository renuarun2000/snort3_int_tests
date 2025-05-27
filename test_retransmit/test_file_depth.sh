#!/bin/bash

# Create the PCAP file
python3 create_pcap.py

# Create a simplified file_magic.rules
cat > file_magic.rules << EOF
# Simple file_magic.rules for testing
file_id (msg:"Test File"; file_meta:type TEST_FILE, id 1, category "Test Files"; file_data; content:"MALWARE", depth 7, offset 0; gid:4; sid:1000; rev:1;)
EOF

# Test with different file_type_depth values
for depth in 1 10 100 1460; do
    echo -e "\nTesting with file_type_depth = $depth"
    echo "=================================="
    
    # Create a test configuration
    cat > test_depth_${depth}.lua << EOF
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
    capture_min_size = 0,         -- No minimum size
    enable_type = true,
    enable_signature = true,
    enable_capture = true,
    trace_type = true,            -- Enable tracing
    rules_file = 'file_magic.rules'
}

-- File policy configuration
file_policy = {
    enable_type = true,
    enable_signature = true,
    enable_capture = true,
    verdict_delay = 0,            -- No delay for testing
    rules = {
        {
            when = { file_type_id = 1 },
            use = { verdict = "block" }
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
    snort -c test_depth_${depth}.lua -r retransmit_test.pcap -A alert_fast -k none -Q -v > depth_${depth}.log 2>&1
    
    # Check if file type was detected
    echo "File type detection results:"
    grep "File type:" depth_${depth}.log || echo "No file type detection"
    
    # Check which packet had the detection
    packet_num=$(grep -B 5 "File type:" depth_${depth}.log | grep "Processing packet" | tail -1 | awk '{print $3}')
    if [ -n "$packet_num" ]; then
        echo "File type detected in packet $packet_num"
    else
        echo "Could not determine packet number for file type detection"
    fi
    
    # Extract file processing information
    echo "File processing information:"
    grep -A 5 "file_data" depth_${depth}.log || echo "No file data processing found"
done

# Create a summary
echo -e "\nSummary of File Type Detection by Depth:"
echo "======================================="
for depth in 1 10 100 1460; do
    packet_num=$(grep -B 5 "File type:" depth_${depth}.log | grep "Processing packet" | tail -1 | awk '{print $3}')
    if [ -n "$packet_num" ]; then
        echo "Depth $depth: File type detected in packet $packet_num"
    else
        echo "Depth $depth: No file type detection"
    fi
done