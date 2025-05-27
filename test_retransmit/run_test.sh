#!/bin/bash

# Start the mock lookup service in the background
python3 mock_lookup_service.py &
LOOKUP_PID=$!

# Give the service time to start
sleep 1

# Create the PCAP file
python3 create_pcap.py

# Run Snort with the configuration
snort -c snort.lua -r retransmit_test.pcap -A alert_fast -k none --daq-dir /usr/local/lib/daq --daq dump --daq-var output=inline-out.pcap -Q -v

# Display the results
echo -e "\n\nResults:"
echo "========"
echo "1. Check if the original packet was held and then retried:"
grep "packet held" snort.log

echo -e "\n2. Check if the retransmitted packet was processed:"
grep "retransmit" snort.log

echo -e "\n3. Check if the malware was detected:"
grep "Malware File Detected" alert_fast.txt

echo -e "\n4. Check if the retry was successful or failed:"
grep "retry" snort.log

# Kill the mock lookup service
kill $LOOKUP_PID