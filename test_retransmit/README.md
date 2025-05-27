# Snort Retransmission Test

This test demonstrates an issue with Snort's handling of retransmitted packets when the original packet is held for file inspection.

## Test Scenario

1. A TCP connection is established
2. An HTTP request is sent for a file
3. The server responds with the file
4. Snort holds the packet containing the file for inspection
5. While the packet is held, a retransmission of the same packet arrives
6. Snort processes the retransmitted packet and advances the TCP stream state
7. After the file verdict is received (as "allow"), Snort attempts to retry the original packet
8. The retry fails because the TCP stream state has advanced

## Files

- `snort.lua`: Snort configuration with file inspection and a 5-second verdict delay
- `create_pcap.py`: Python script to create a test PCAP file
- `run_test.sh`: Shell script to run the test
- `retransmit_test.pcap`: Generated PCAP file with the test scenario

## Expected Results

1. The original packet containing "MALWARE" is held for inspection
2. The retransmitted packet is processed while the original is held
3. The file is detected and allowed (log verdict)
4. When Snort attempts to retry the original packet, it fails due to invalid sequence numbers

## Actual Results

The test shows that:

1. Retransmitted packets are also queued for retry, which is unnecessary
2. The partial flush for retransmitted packets advances the TCP stream state
3. When the original packet is retried, it's rejected due to invalid sequence numbers

## Proposed Fix

1. Don't queue retransmitted packets for retry
2. Don't perform partial flush for retransmitted packets that will be dropped
3. Cancel pending retries for held packets when a retransmission is processed

## Running the Test

```
./run_test.sh
```