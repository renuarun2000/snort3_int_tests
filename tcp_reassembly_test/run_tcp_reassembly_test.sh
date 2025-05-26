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
python3 generate_tcp_reassembly_test_pcap.py

# Check if PCAP was generated
if [ ! -f "$PCAP_FILE" ]; then
    echo "Error: Failed to generate PCAP file"
    exit 1
fi

# Run Snort with the test configuration
echo "Running Snort with TCP reassembly test configuration..."
$SNORT_BIN -c $CONFIG_FILE -r $PCAP_FILE -A csv -l $OUTPUT_DIR --plugin-path=/usr/local/lib/snort/plugins

# Check Snort exit status
if [ $? -ne 0 ]; then
    echo "Error: Snort execution failed"
    exit 1
fi

# Analyze the results
echo "Analyzing results..."
if [ -f "$OUTPUT_DIR/alert.csv" ]; then
    echo "Alerts generated:"
    cat $OUTPUT_DIR/alert.csv
else
    echo "No alerts generated."
fi

# Check for TCP reassembly issues in Snort logs
if grep -q "TCP Reassembly" $OUTPUT_DIR/snort.log 2>/dev/null; then
    echo "TCP reassembly issues detected in logs."
    grep "TCP Reassembly" $OUTPUT_DIR/snort.log
fi

# Print summary
echo "Test completed. Check $OUTPUT_DIR directory for detailed results."
echo "To analyze packet processing in detail, examine $OUTPUT_DIR/snort.log"

exit 0
