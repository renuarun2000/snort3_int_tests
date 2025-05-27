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

# Create a test configuration to force early detection
cat > force_early_large.lua << EOF
-- Basic network settings
HOME_NET = "10.1.0.0/16"
EXTERNAL_NET = "any"

-- Include default configurations
dofile('snort_defaults.lua')

-- Stream configuration with aggressive settings
stream = { }
stream_tcp = { 
    show_rebuilt_packets = true,
    session_timeout = 180,
    flush_factor = 0,
    small_segments = {
        count = 1,            -- Consider even a single segment as "small"
        maximum_size = 1460   -- Maximum segment size
    },
    flush_behavior = "large"  -- Flush on large segments
}

-- HTTP Inspector with settings to force early detection
http_inspect = { 
    response_depth = 0,       -- Unlimited response depth
    request_depth = 0,        -- Unlimited request depth
    file_depth = 1460,        -- One full TCP segment
    decompress_pdf = true,
    decompress_swf = true,
    decompress_zip = true,
    decompress_vba = true
}

-- File ID configuration with small depth
file_id = {
    type_depth = 8,           -- Just enough to detect "MALWARE"
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
        stream_tcp = { all = 2 },
        http_inspect = { all = 3 }
    }
}
EOF

# Run Snort with this configuration
echo "Running Snort with forced early detection configuration..."
snort -c force_early_large.lua -r large_file.pcap -A alert_fast -k none -Q -v > force_early_large.log 2>&1

# Check if file type was detected
echo -e "\nFile type detection results:"
echo "============================"
grep "File type:" force_early_large.log || echo "No file type detection"

# Check which packet had the detection
packet_num=$(grep -B 5 "File type:" force_early_large.log | grep "Processing packet" | tail -1 | awk '{print $3}')
if [ -n "$packet_num" ]; then
    echo "File type detected in packet $packet_num"
    
    # Get total number of packets
    total_packets=$(grep "Processing packet" force_early_large.log | wc -l)
    echo "Total packets: $total_packets"
    
    # Calculate percentage of file processed before detection
    percentage=$(echo "scale=2; $packet_num * 100 / $total_packets" | bc)
    echo "File type detected after processing $percentage% of packets"
    
    # Extract file processing information
    echo -e "\nFile processing information:"
    echo "============================="
    grep -A 5 "file_data" force_early_large.log | head -10
else
    echo "Could not determine packet number for file type detection"
fi

echo -e "\nFull log is available in force_early_large.log"