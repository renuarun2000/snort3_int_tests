#!/bin/bash
# Script to run the PAWS timestamp validation test with Snort

# Set variables
SNORT_BIN="snort"
CONFIG_FILE="snort_paws_test.lua"
PCAP_FILE="paws_test.pcap"
OUTPUT_DIR="output"

# Create output directory
mkdir -p $OUTPUT_DIR

# Generate the PCAP file
echo "Generating PCAP file with PAWS timestamp violation..."
python3 generate_paws_test_pcap.py

# Validate Snort configuration
echo "Validating Snort configuration..."
$SNORT_BIN -c $CONFIG_FILE -T

# Run Snort with the test PCAP
echo "Running Snort with PAWS test PCAP..."
$SNORT_BIN -c $CONFIG_FILE -r $PCAP_FILE -A csv -l $OUTPUT_DIR -v

# Display results
echo "Test completed. Check the following files for results:"
echo "- $OUTPUT_DIR/alert.csv - For alerts related to timestamp violations"
echo "- $OUTPUT_DIR/snort.log.* - For packet capture logs"

# Extract relevant alerts
echo "Extracting PAWS-related alerts..."
grep "Timestamp" $OUTPUT_DIR/alert.csv

# Analyze TCP events
echo "TCP events from the test:"
grep "TCP" $OUTPUT_DIR/alert.csv