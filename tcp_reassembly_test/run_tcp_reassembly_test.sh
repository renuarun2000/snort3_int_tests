#!/bin/bash
# Script to run the TCP reassembly test with Snort

# Set variables
SNORT_BIN="snort"
CONFIG_FILE="snort_tcp_reassembly_test.lua"
PCAP_FILE="tcp_reassembly_test.pcap"
OUTPUT_DIR="output"

# Create output directory
mkdir -p $OUTPUT_DIR

# Generate the PCAP file
echo "Generating PCAP file with TCP reassembly test conditions..."
python3