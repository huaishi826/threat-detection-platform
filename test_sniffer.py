"""Quick verification for TrafficSniffer.

Usage:
    python test_sniffer.py [duration_sec]
        duration_sec = capture window (default 15 seconds)

Steps:
    1. Starts capture for N seconds
    2. Prints protocol stats
    3. Verifies TCP, DNS, UDP or ICMP appeared
    4. Prints flow summary
    5. Prints time-series data
"""

import sys
import time
from sniffer import TrafficSniffer


def main():
    dur = int(sys.argv[1]) if len(sys.argv) > 1 else 15
    pcap_file = "test_traffic.pcap"

    print(f"[*] Test capture ({dur}s) ...")
    print(f"    Open a browser and visit a few websites NOW to generate traffic!\n")

    sniffer = TrafficSniffer(timeout=dur)
    sniffer.start_capture(pcap_file)
    sniffer._stop_event.wait()

    print(f"\n{'='*50}")
    print(f"  ANALYSIS")
    print(f"{'='*50}")

    # Protocol stats
    stats = TrafficSniffer.get_protocol_stats(pcap_file)
    print(f"\n--- Protocol Statistics ---")
    for proto, data in stats.items():
        print(f"  {proto:8s}  packets={data['packets']:>6d}  bytes={data['bytes']:>10d}")

    # Flow summary
    flow = TrafficSniffer.get_flow_summary(pcap_file)
    print(f"\n--- Flow Summary ---")
    for k, v in flow.items():
        print(f"  {k}: {v}")

    # Time series
    ts = TrafficSniffer.get_protocol_timeseries(pcap_file, window_sec=5)
    print(f"\n--- Time Series (5s bins) ---")
    for entry in ts:
        print(f"  {entry}")

    # Verify
    print(f"\n{'='*50}")
    print(f"  VERIFICATION")
    print(f"{'='*50}")
    tcp_ok = stats['TCP']['packets'] > 0
    dns_ok = stats['DNS']['packets'] > 0
    udp_ok = stats['UDP']['packets'] > 0
    tls_ok = stats['TLS/SSL']['packets'] > 0
    ts_ok = len(ts) > 0
    flow_ok = flow['total_packets'] > 0

    print(f"  TCP  detected: {'PASS' if tcp_ok else 'FAIL'}")
    print(f"  DNS  detected: {'PASS' if dns_ok else 'FAIL (try browsing)'}")
    print(f"  UDP  detected: {'PASS' if udp_ok else 'FAIL'}")
    print(f"  TLS  detected: {'PASS' if tls_ok else 'FAIL (try HTTPS)'}")
    print(f"  TimeSeries:    {'PASS' if ts_ok else 'FAIL'}")
    print(f"  FlowSummary:   {'PASS' if flow_ok else 'FAIL'}")

    all_pass = tcp_ok and ts_ok and flow_ok
    if all_pass:
        print(f"\n  CORE CHECKS PASSED")
    else:
        print(f"\n  FAILED -- check Wireshark/Npcap installation")


if __name__ == '__main__':
    main()
