"""
Rule-based threat detection engine.

Detects three attack patterns from pcap files:
  1. SYN Flood  — high-volume TCP SYN without completing handshake
  2. DNS Tunnel — suspicious DNS query patterns (long domains, high frequency)
  3. Port Scan  — single source probing many destination ports

Each detector returns a list of alert dicts with keys:
  timestamp, type, severity, source_ip, detail
"""

import json
import os
import datetime
from collections import defaultdict


# ─── config loader ───────────────────────────────────────────────────

_CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")


def load_rules_config():
    """Read detection thresholds from config.json."""
    try:
        with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        return {
            "syn_flood": cfg.get("syn_flood", {}),
            "dns_tunnel": cfg.get("dns_tunnel", {}),
            "port_scan": cfg.get("port_scan", {}),
        }
    except Exception:
        # fallback defaults if config.json is missing
        return {
            "syn_flood": {"window": 10, "threshold": 0.7, "min_packets": 100},
            "dns_tunnel": {"window": 60, "query_threshold": 50, "length_threshold": 40},
            "port_scan": {"window": 30, "port_threshold": 20},
        }

import pyshark


# ─── helpers ────────────────────────────────────────────────────────

def _open_pcap(pcap_file):
    """Open a pcap file with PyShark (text mode)."""
    return pyshark.FileCapture(
        pcap_file,
        tshark_path=r"C:\Program Files\Wireshark\tshark.exe",
    )


def _get_sniff_time(pkt):
    """Safely extract sniff datetime from a packet."""
    try:
        return pkt.sniff_time
    except (ValueError, TypeError):
        raw = str(getattr(pkt, "sniff_timestamp", ""))
        try:
            return datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except Exception:
            return None


def _tcp_flag_set(pkt, flag):
    """Check if a TCP flag is set. flag: 'syn','ack','rst','fin','psh','urg'.

    PyShark 0.6 exposes flags as:
      - pkt.tcp.flags_syn  ('1' / '0')
      - pkt.tcp.flags      (hex string like '0x0002')
    """
    attr_name = f"flags_{flag}"
    try:
        val = getattr(pkt.tcp, attr_name, None)
        if val is not None:
            return str(val) in ("1", "true", "True")
    except Exception:
        pass

    # fallback: parse hex flags
    try:
        hex_val = int(getattr(pkt.tcp, "flags", "0"), 16)
        bit_map = {"syn": 0x02, "ack": 0x10, "rst": 0x04, "fin": 0x01,
                    "psh": 0x08, "urg": 0x20}
        return bool(hex_val & bit_map.get(flag, 0))
    except Exception:
        return False


# ─── detector 1: SYN Flood ──────────────────────────────────────────

def detect_syn_flood(pcap_file, window=None, threshold=None, min_packets=None):
    """Detect SYN flood attacks.

    A SYN flood sends massive TCP SYN packets without completing the
    3-way handshake, exhausting server resources.

    Args:
        pcap_file:   Path to .pcap file.
        window:      Time window size in seconds (default from config).
        threshold:   SYN ratio threshold (0-1) (default from config).
        min_packets: Minimum TCP packets in window (default from config).

    Returns:
        list[dict]  Alerts sorted by timestamp.
    """
    cfg = load_rules_config()["syn_flood"]
    if window is None:
        window = cfg.get("window", 10)
    if threshold is None:
        threshold = cfg.get("threshold", 0.7)
    if min_packets is None:
        min_packets = cfg.get("min_packets", 100)

    alerts = []
    windows = defaultdict(lambda: {"syn": 0, "tcp": 0, "first_ts": None})

    try:
        cap = _open_pcap(pcap_file)
        for pkt in cap:
            try:
                if not hasattr(pkt, "tcp"):
                    continue
                ts = _get_sniff_time(pkt)
                if ts is None:
                    continue
                win_key = int(ts.timestamp() // window)
                w = windows[win_key]
                w["tcp"] += 1
                if w["first_ts"] is None:
                    w["first_ts"] = ts
                if _tcp_flag_set(pkt, "syn") and not _tcp_flag_set(pkt, "ack"):
                    w["syn"] += 1
            except Exception:
                continue
        cap.close()
    except Exception as exc:
        print(f"[!] Error reading pcap: {exc}")

    for win_key, data in sorted(windows.items()):
        if data["tcp"] < min_packets:
            continue
        ratio = data["syn"] / data["tcp"] if data["tcp"] > 0 else 0
        if ratio > threshold:
            alerts.append({
                "timestamp": data["first_ts"].isoformat() if data["first_ts"]
                    else f"window_{win_key}",
                "type": "SYN_Flood",
                "severity": "high",
                "source_ip": "N/A",
                "detail": (f"SYN ratio {ratio:.1%} in {data['tcp']} TCP packets "
                           f"({data['syn']} SYN-only, window {window}s)"),
            })

    return alerts


# ─── detector 2: DNS Tunnel ─────────────────────────────────────────

def detect_dns_tunnel(pcap_file, window=None, query_threshold=None,
                      length_threshold=None):
    """Detect DNS tunnelling.

    DNS tunnelling encodes data in long, high-frequency DNS queries.
    Indicators: unusually many queries to one domain, or very long
    query names (>40 chars).

    Args:
        pcap_file:         Path to .pcap file.
        window:            Time window in seconds (default from config).
        query_threshold:   Max queries per domain in window (default from config).
        length_threshold:  Max average query-name length (default from config).

    Returns:
        list[dict]  Alerts sorted by timestamp.
    """
    cfg = load_rules_config()["dns_tunnel"]
    if window is None:
        window = cfg.get("window", 60)
    if query_threshold is None:
        query_threshold = cfg.get("query_threshold", 50)
    if length_threshold is None:
        length_threshold = cfg.get("length_threshold", 40)

    alerts = []
    dns_data = defaultdict(lambda: defaultdict(
        lambda: {"count": 0, "total_len": 0, "first_ts": None}))

    try:
        cap = _open_pcap(pcap_file)
        for pkt in cap:
            try:
                if not hasattr(pkt, "dns"):
                    continue
                ts = _get_sniff_time(pkt)
                if ts is None:
                    continue
                win_key = int(ts.timestamp() // window)
                qname = getattr(pkt.dns, "qry_name", None)
                src_ip = getattr(pkt.ip, "src", "unknown") if hasattr(pkt, "ip") \
                    else "unknown"
                if qname:
                    entry = dns_data[win_key][qname]
                    entry["count"] += 1
                    entry["total_len"] += len(qname)
                    if entry["first_ts"] is None:
                        entry["first_ts"] = ts
                    entry["src_ip"] = src_ip
            except Exception:
                continue
        cap.close()
    except Exception as exc:
        print(f"[!] Error reading pcap: {exc}")

    for win_key, domains in sorted(dns_data.items()):
        for qname, data in domains.items():
            avg_len = data["total_len"] / data["count"] if data["count"] else 0
            if data["count"] > query_threshold or avg_len > length_threshold:
                alerts.append({
                    "timestamp": data["first_ts"].isoformat() if data.get("first_ts")
                        else f"window_{win_key}",
                    "type": "DNS_Tunnel",
                    "severity": "medium",
                    "source_ip": data.get("src_ip", "N/A"),
                    "detail": (f"Domain '{qname}': {data['count']} queries, "
                               f"avg length {avg_len:.1f} chars"),
                })

    return alerts


# ─── detector 3: Port Scan ──────────────────────────────────────────

def detect_port_scan(pcap_file, window=None, port_threshold=None):
    """Detect horizontal port scans.

    A port scan probes many different ports on one or more hosts.
    Detects when a single source IP connects to >port_threshold
    unique destination ports in a time window.

    Args:
        pcap_file:      Path to .pcap file.
        window:         Time window in seconds (default from config).
        port_threshold: Max unique ports before alerting (default from config).

    Returns:
        list[dict]  Alerts sorted by timestamp.
    """
    cfg = load_rules_config()["port_scan"]
    if window is None:
        window = cfg.get("window", 30)
    if port_threshold is None:
        port_threshold = cfg.get("port_threshold", 20)

    alerts = []
    scan_data = defaultdict(lambda: defaultdict(
        lambda: {"ports": set(), "first_ts": None}))

    try:
        cap = _open_pcap(pcap_file)
        for pkt in cap:
            try:
                if not hasattr(pkt, "ip"):
                    continue
                # try transport layer port
                dst_port = None
                for layer_name in ("tcp", "udp"):
                    layer = getattr(pkt, layer_name, None)
                    if layer:
                        dp = getattr(layer, "dstport", None)
                        if dp:
                            dst_port = int(dp)
                            break
                if dst_port is None:
                    continue

                ts = _get_sniff_time(pkt)
                if ts is None:
                    continue

                src_ip = pkt.ip.src
                win_key = int(ts.timestamp() // window)
                entry = scan_data[win_key][src_ip]
                entry["ports"].add(dst_port)
                if entry["first_ts"] is None:
                    entry["first_ts"] = ts
            except Exception:
                continue
        cap.close()
    except Exception as exc:
        print(f"[!] Error reading pcap: {exc}")

    for win_key, sources in sorted(scan_data.items()):
        for src_ip, data in sources.items():
            if len(data["ports"]) > port_threshold:
                sorted_ports = sorted(data["ports"])[:20]
                alerts.append({
                    "timestamp": data["first_ts"].isoformat() if data["first_ts"]
                        else f"window_{win_key}",
                    "type": "Port_Scan",
                    "severity": "medium",
                    "source_ip": src_ip,
                    "detail": (f"{len(data['ports'])} unique ports in {window}s: "
                               f"{sorted_ports}{'...' if len(data['ports']) > 20 else ''}"),
                })

    return alerts


# ─── combined ────────────────────────────────────────────────────────

def detect_all(pcap_file):
    """Run all rule detectors and return a merged, time-sorted alert list."""
    alerts = []
    alerts.extend(detect_syn_flood(pcap_file))
    alerts.extend(detect_dns_tunnel(pcap_file))
    alerts.extend(detect_port_scan(pcap_file))
    alerts.sort(key=lambda a: a.get("timestamp", ""))
    return alerts


# ─── main ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    pcap = sys.argv[1] if len(sys.argv) > 1 else "quick_test.pcap"

    print(f"[*] Rule-based detection on: {pcap}")
    results = detect_all(pcap)

    if not results:
        print("  No alerts -- traffic looks clean.")
    else:
        print(f"  {len(results)} alert(s):\n")
        for a in results:
            print(f"  [{a['severity'].upper():6s}] {a['type']:15s}  "
                  f"{a['timestamp']}  src={a['source_ip']}")
            print(f"         {a['detail']}\n")
