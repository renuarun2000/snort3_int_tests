# Snort PAWS Timestamp Validation Test

This test demonstrates how Snort handles TCP packets with timestamps in the past (PAWS violations).

## Prerequisites

- Snort 3.x installed
- Python 3.x with Scapy library (`pip install scapy`)
- Basic understanding of TCP and Snort

## Files

- `snort_paws_test.lua`: Snort configuration file with TCP normalization enabled
- `generate_paws_test_pcap.py`: Python script to generate a PCAP with PAWS violations
- `run_paws_test.sh`: Shell script to run the test
- `paws_test.pcap`: Generated PCAP file with TCP packets having timestamp issues

## Running the Test

1. Make sure Snort is installed and in your PATH
2. Install Scapy: `pip install scapy`
3. Make the scripts executable:
   ```
   chmod +x generate_paws_test_pcap.py run_paws_test.sh
   ```
4. Run the test:
   ```
   ./run_paws_test.sh
   ```

## What to Look For

The test creates a TCP session with normal timestamp progression, then injects a packet with a timestamp in the past. Snort should:

1. Establish the TCP session normally
2. Detect the PAWS violation (packet #8 in the PCAP)
3. Generate an alert for the bad timestamp
4. Potentially drop the packet with the old timestamp
5. Continue processing subsequent packets with valid timestamps

## Expected Output

You should see alerts in the `output/alert.csv` file related to timestamp violations. The specific alert will depend on your Snort version and configuration, but should include something like:

```
TCP PAWS Timestamp Violation
```

or

```
TCP Bad Timestamp
```

## Explanation

The PAWS (Protection Against Wrapped Sequence numbers) mechanism in TCP uses timestamps to prevent old duplicate segments from being accepted. When Snort sees a packet with a timestamp older than previously seen packets in the same TCP session, it treats this as suspicious and can generate alerts or drop the packet.

This test demonstrates how Snort's TCP stream reassembly and normalization handles such cases, which could be legitimate network issues or potential attacks.