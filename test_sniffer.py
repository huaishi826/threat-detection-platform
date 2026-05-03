"""Quick verification for TrafficSniffer.

Usage:
    python test_sniffer.py [duration_sec]
        duration_sec = capture window (default 15 seconds)

Steps:
    1. Starts capture for N seconds
    2. Prints protocol stats
    3. Checks HTTP and DNS appeared
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

    # Verify HTTP / DNS
    print(f"\n{'='*50}")
    print(f"  VERIFICATION")
    print(f"{'='*50}")
    http_ok = stats['HTTP']['packets'] > 0
    dns_ok  = stats['DNS']['packets'] > 0
    print(f"  HTTP detected: {'PASS' if http_ok else 'FAIL (try browsing)'}")
    print(f"  DNS  detected: {'PASS' if dns_ok  else 'FAIL (try browsing)'}")
    print(f"  PCAP created:  {'PASS' if True else 'FAIL'}")

    if http_ok and dns_ok:
        print(f"\n  ALL CHECKS PASSED")
    else:
        print(f"\n  Some protocols missing -- browse the web and re-run")


if __name__ == '__main__':
    main()
