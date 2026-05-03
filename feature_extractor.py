"""
Feature extraction from pcap files for ML anomaly detection.

Extracts 15 features per time window:
  - Traffic volume: pps, avg packet size
  - TCP flag ratios: SYN, ACK, RST, FIN
  - Diversity: unique dst ports, unique src IPs
  - Protocol mix: TCP, UDP, DNS, ICMP ratios
  - Direction: inbound, outbound ratios

Output: numpy array of shape [n_windows, 15]
"""

import datetime
import socket
from collections import defaultdict

import numpy as np
import pyshark


# ─── helpers ────────────────────────────────────────────────────────

def _get_local_ip():
    """Best-effort local IP detection."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _get_sniff_time(pkt):
    """Safely extract sniff datetime."""
    try:
        return pkt.sniff_time
    except (ValueError, TypeError):
        try:
            raw = str(getattr(pkt, "sniff_timestamp", ""))
            return datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except Exception:
            return None


def _tcp_flag_set(pkt, flag):
    """Check if a TCP flag is set."""
    try:
        val = getattr(pkt.tcp, f"flags_{flag}", None)
        if val is not None:
            return str(val) in ("1", "true", "True")
    except Exception:
        pass
    try:
        hex_val = int(getattr(pkt.tcp, "flags", "0"), 16)
        bit_map = {"syn": 0x02, "ack": 0x10, "rst": 0x04, "fin": 0x01}
        return bool(hex_val & bit_map.get(flag, 0))
    except Exception:
        return False


# ─── extractor class ────────────────────────────────────────────────

class FeatureExtractor:
    """Extract time-windowed feature vectors from network traffic.

    Usage:
        fe = FeatureExtractor(window_size=10)
        matrix = fe.extract("traffic.pcap")  # shape [n_windows, 15]
        names  = fe.get_feature_names()       # list[str]
    """

    FEATURE_NAMES = [
        "packets_per_sec",        # 0
        "avg_packet_size",        # 1
        "syn_ratio",              # 2
        "ack_ratio",              # 3
        "rst_ratio",              # 4
        "fin_ratio",              # 5
        "unique_dst_ports",       # 6
        "unique_src_ips",         # 7
        "tcp_ratio",              # 8
        "udp_ratio",              # 9
        "dns_ratio",              # 10
        "icmp_ratio",             # 11
        "inbound_ratio",          # 12
        "outbound_ratio",         # 13
    ]

    def __init__(self, window_size=10):
        self.window_size = window_size

    # ── public API ──────────────────────────────────────────────────

    def extract(self, pcap_file):
        """Extract feature matrix from a pcap file.

        Args:
            pcap_file: Path to .pcap file.

        Returns:
            np.ndarray of shape [n_windows, 15], or [0, 15] if empty.
        """
        local_ip = _get_local_ip()
        windows = defaultdict(lambda: {
            "packets": 0, "total_bytes": 0,
            "syn": 0, "ack": 0, "rst": 0, "fin": 0,
            "tcp": 0, "udp": 0, "dns": 0, "icmp": 0,
            "ports": set(), "src_ips": set(),
            "inbound": 0, "outbound": 0,
            "order": None,
        })

        try:
            cap = pyshark.FileCapture(
                pcap_file,
                tshark_path=r"C:\Program Files\Wireshark\tshark.exe",
            )
            for pkt in cap:
                try:
                    ts = _get_sniff_time(pkt)
                    if ts is None:
                        continue
                    pkt_size = int(pkt.length)
                    win_key = int(ts.timestamp() // self.window_size)
                    w = windows[win_key]
                    if w["order"] is None:
                        w["order"] = ts
                    w["packets"] += 1
                    w["total_bytes"] += pkt_size

                    # protocol flags
                    proto_names = {p.layer_name.upper() for p in pkt.layers}

                    if hasattr(pkt, "tcp"):
                        w["tcp"] += 1
                        if _tcp_flag_set(pkt, "syn"):
                            w["syn"] += 1
                        if _tcp_flag_set(pkt, "ack"):
                            w["ack"] += 1
                        if _tcp_flag_set(pkt, "rst"):
                            w["rst"] += 1
                        if _tcp_flag_set(pkt, "fin"):
                            w["fin"] += 1
                        try:
                            w["ports"].add(int(pkt.tcp.dstport))
                        except Exception:
                            pass

                    if hasattr(pkt, "udp"):
                        w["udp"] += 1
                        try:
                            w["ports"].add(int(pkt.udp.dstport))
                        except Exception:
                            pass

                    if "DNS" in proto_names:
                        w["dns"] += 1
                    if "ICMP" in proto_names or "ICMPV6" in proto_names:
                        w["icmp"] += 1

                    # src IPs / direction
                    if hasattr(pkt, "ip"):
                        w["src_ips"].add(pkt.ip.src)
                        if pkt.ip.dst == local_ip:
                            w["inbound"] += 1
                        elif pkt.ip.src == local_ip:
                            w["outbound"] += 1
                    elif hasattr(pkt, "ipv6"):
                        w["src_ips"].add(pkt.ipv6.src)
                        if pkt.ipv6.dst == local_ip:
                            w["inbound"] += 1
                        elif pkt.ipv6.src == local_ip:
                            w["outbound"] += 1

                except Exception:
                    continue
            cap.close()
        except Exception as exc:
            print(f"[!] Error: {exc}")

        return self._build_matrix(windows)

    def extract_from_live(self, interface=None, duration=60):
        """Capture live traffic and extract features.

        Args:
            interface: NPF device path (None = auto).
            duration:  Capture seconds.

        Returns:
            np.ndarray of shape [n_windows, 15].
        """
        import tempfile, os
        pcap_path = os.path.join(tempfile.gettempdir(), "_feat_capture.pcap")
        from sniffer import TrafficSniffer
        sniffer = TrafficSniffer(interface=interface, timeout=duration)
        sniffer.start_capture(pcap_path)
        sniffer._stop_event.wait()
        return self.extract(pcap_path)

    def get_feature_names(self):
        """Return feature name list."""
        return list(self.FEATURE_NAMES)

    # ── internal ────────────────────────────────────────────────────

    def _build_matrix(self, windows):
        """Convert windowed data to numpy feature matrix."""
        ordered = sorted(
            ((k, v) for k, v in windows.items() if v["order"] is not None),
            key=lambda x: x[1]["order"],
        )

        if not ordered:
            return np.empty((0, len(self.FEATURE_NAMES)))

        rows = []
        for _key, w in ordered:
            pps = w["packets"] / self.window_size
            avg_size = w["total_bytes"] / w["packets"] if w["packets"] else 0
            syn_r = w["syn"] / w["tcp"] if w["tcp"] else 0
            ack_r = w["ack"] / w["tcp"] if w["tcp"] else 0
            rst_r = w["rst"] / w["tcp"] if w["tcp"] else 0
            fin_r = w["fin"] / w["tcp"] if w["tcp"] else 0
            n_ports = len(w["ports"])
            n_srcs = len(w["src_ips"])
            tcp_r = w["tcp"] / w["packets"] if w["packets"] else 0
            udp_r = w["udp"] / w["packets"] if w["packets"] else 0
            dns_r = w["dns"] / w["packets"] if w["packets"] else 0
            icmp_r = w["icmp"] / w["packets"] if w["packets"] else 0
            inb_r = w["inbound"] / w["packets"] if w["packets"] else 0
            outb_r = w["outbound"] / w["packets"] if w["packets"] else 0

            rows.append([
                round(pps, 4), round(avg_size, 2),
                round(syn_r, 4), round(ack_r, 4), round(rst_r, 4), round(fin_r, 4),
                n_ports, n_srcs,
                round(tcp_r, 4), round(udp_r, 4), round(dns_r, 4), round(icmp_r, 4),
                round(inb_r, 4), round(outb_r, 4),
            ])

        return np.array(rows, dtype=np.float64)


# ─── main ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    pcap = sys.argv[1] if len(sys.argv) > 1 else "quick_test.pcap"

    fe = FeatureExtractor(window_size=10)
    print(f"[*] Extracting features from: {pcap}")
    X = fe.extract(pcap)

    if X.shape[0] == 0:
        print("[!] Empty pcap or no data in window.")
    else:
        print(f"  Shape: {X.shape}")
        print(f"  Features: {fe.get_feature_names()}\n")
        print(f"  First {min(3, X.shape[0])} windows:")
        print(f"  {X[:3]}")
