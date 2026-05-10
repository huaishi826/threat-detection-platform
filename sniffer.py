import tempfile, os, datetime, subprocess, threading
import logging
import pyshark

logger = logging.getLogger(__name__)

# TShark path: env var > default
_DEFAULT_TSHARK = os.environ.get("TSHARK_PATH", "tshark")

# Protocol matching rules: (display_name, set_of_layer_names_to_match)
_PROTOCOL_RULES = [
    ('HTTP',    {'HTTP'}),
    ('DNS',     {'DNS'}),
    ('TCP',     {'TCP'}),
    ('UDP',     {'UDP'}),
    ('ICMP',    {'ICMP', 'ICMPV6'}),
    ('TLS/SSL', {'TLS', 'SSL'}),
    ('ARP',     {'ARP'}),
]

_TIMESERIES_PROTOS = ['HTTP', 'DNS', 'TCP', 'UDP', 'ICMP']
_TIMESERIES_LAYER_MAP = {
    'HTTP': {'HTTP'}, 'DNS': {'DNS'}, 'TCP': {'TCP'},
    'UDP': {'UDP'}, 'ICMP': {'ICMP', 'ICMPV6'},
}


def _init_proto_stats():
    """Create a zeroed protocol stats dict."""
    return {name: {'packets': 0, 'bytes': 0} for name, _ in _PROTOCOL_RULES}


def _count_protocols(proto_names, pkt_size, stats):
    """Update protocol stats dict in-place based on layer names."""
    for name, layers in _PROTOCOL_RULES:
        if proto_names & layers:
            stats[name]['packets'] += 1
            stats[name]['bytes'] += pkt_size


def _count_timeseries_proto(proto_names, bucket, timeseries):
    """Update timeseries bucket counters in-place."""
    for proto, layers in _TIMESERIES_LAYER_MAP.items():
        if proto_names & layers:
            timeseries[bucket][proto] += 1


class TrafficSniffer:
    """Traffic capture and protocol analysis engine.

    Wraps PyShark (TShark) to provide real-time packet capture,
    protocol statistics, flow summaries, and time-series data
    for dashboard visualization.

    Attributes:
        interface: Network interface name, None = auto-select first non-loopback.
        timeout:   Max capture duration in seconds.
    """

    PROTOCOLS = ['HTTP', 'DNS', 'TCP', 'UDP', 'ICMP', 'TLS', 'ARP']

    def __init__(self, interface=None, timeout=60, tshark_path=None):
        self.interface = interface
        self.timeout = timeout
        self._capture = None
        self._stop_event = threading.Event()
        self._tshark = tshark_path or _DEFAULT_TSHARK

    def _auto_interface(self):
        """Return best available network interface via tshark -D.

        Cross-platform: Windows (\\Device\\NPF_xxx) and Linux (eth0/wlan0).
        """
        try:
            result = subprocess.run(
                [self._tshark, "-D"],
                capture_output=True, text=False, timeout=10,
            )
            # Try UTF-8 (Linux) then GBK (Windows)
            raw = None
            for enc in ("utf-8", "gbk"):
                try:
                    raw = result.stdout.decode(enc, errors="replace")
                    if raw.strip():
                        break
                except Exception:
                    continue
            if not raw or not raw.strip():
                raw = result.stdout.decode("utf-8", errors="replace")

            is_windows = os.name == "nt"
            preferred_win = ["WLAN", "Wi-Fi", "\u4ee5\u592a\u7f51", "Ethernet"]
            # In Docker, 'any' interface captures traffic across all virtual interfaces
            # Don't prefer eth0/wlan0 etc. individually - 'any' covers them all
            preferred_linux = ["any"]

            candidates = []  # (name, is_preferred)
            for line in raw.splitlines():
                line = line.strip()
                if not line:
                    continue
                if is_windows:
                    if "\\Device\\NPF_" not in line:
                        continue
                    if "Loopback" in line or "etwdump" in line:
                        continue
                    start = line.index("\\Device\\NPF_")
                    end = line.index(" ", start) if " " in line[start:] else len(line)
                    iface = line[start:end]
                    adapter = line[end:].strip(" ()")
                    is_pref = any(kw.lower() in adapter.lower() for kw in preferred_win)
                    candidates.append((iface, is_pref, adapter))
                else:
                    # Linux: "1. eth0" or "2. any"
                    parts = line.split(".", 1)
                    if len(parts) < 2:
                        continue
                    iface = parts[1].strip().split()[0]
                    if iface in ("lo", "bluetooth-monitor", "nflog", "nfqueue"):
                        continue
                    is_pref = any(iface.startswith(kw) for kw in preferred_linux)
                    candidates.append((iface, is_pref, iface))

            if not candidates:
                return "lo" if not is_windows else "\\Device\\NPF_Loopback"

            # Prefer first preferred candidate, then first non-loopback
            for name, is_pref, adapter in candidates:
                if is_pref:
                    print(f"    Auto-selected preferred: {name}")
                    return name
            print(f"    Auto-selected fallback: {candidates[0][0]}")
            return candidates[0][0]
        except Exception as exc:
            print(f"    Interface detection failed: {exc}")
        return "lo" if os.name != "nt" else "\\Device\\NPF_Loopback"

    def start_capture(self, pcap_filename):
        """Start live capture on background thread.

        Packets are saved to pcap_filename. Capture stops
        automatically after self.timeout seconds or when
        stop_capture() is called.
        """
        iface = self.interface or self._auto_interface()
        print(f"[*] Starting capture on '{iface}' for {self.timeout}s ...")
        print(f"    Output: {pcap_filename}")

        self._stop_event.clear()
        # Capture thread result (None=not done, str=error message, True=success)
        self._capture_result = [None]

        def _traffic_generator():
            """Generate minimal background traffic to ensure capture has packets."""
            import socket
            while not self._stop_event.is_set():
                try:
                    # DNS lookup
                    socket.setdefaulttimeout(2)
                    socket.getaddrinfo("dns.alidns.com", 53)
                except Exception:
                    pass
                try:
                    # HTTP request
                    import urllib.request
                    urllib.request.urlopen("http://localhost:5000/api/health", timeout=2)
                except Exception:
                    pass
                self._stop_event.wait(timeout=3)

        def _run():
            try:
                cmd = [self._tshark, "-i", iface, "-w", pcap_filename,
                       "-a", "duration:" + str(self.timeout)]
                self._capture = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                # Start background traffic generator
                _traffic_thread = threading.Thread(target=_traffic_generator, daemon=True)
                _traffic_thread.start()
                # Wait for process to finish or stop event
                while self._capture.poll() is None:
                    if self._stop_event.wait(timeout=0.5):
                        self._capture.terminate()
                        break
                try:
                    self._capture.wait(timeout=5)
                except Exception:
                    self._capture.kill()
                # Read stderr for error messages
                err_raw = b""
                try:
                    _, err_raw = self._capture.communicate(timeout=3)
                except Exception:
                    pass
                err_msg = ""
                if err_raw:
                    for enc in ("utf-8", "gbk"):
                        try:
                            err_msg = err_raw.decode(enc, errors="replace")
                            break
                        except Exception:
                            continue
                # Check pcap file size to determine success
                pcap_ok = os.path.exists(pcap_filename) and os.path.getsize(pcap_filename) > 356
                if pcap_ok:
                    self._capture_result[0] = True
                elif err_msg and "Permission denied" in err_msg:
                    self._capture_result[0] = "Permission denied. Please run as Administrator."
                elif err_msg:
                    self._capture_result[0] = "Capture error: " + err_msg.strip()[:200]
                else:
                    self._capture_result[0] = True  # Empty but no error (no traffic)
            except PermissionError:
                self._capture_result[0] = "Permission denied. Please run as Administrator."
            except Exception as exc:
                if not self._stop_event.is_set():
                    self._capture_result[0] = str(exc)[:200]
                else:
                    self._capture_result[0] = True
            finally:
                try:
                    if self._capture and self._capture.poll() is None:
                        self._capture.terminate()
                except Exception:
                    pass
                print("[*] Capture finished.")

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        # NOTE: No Timer here - let tshark finish naturally via -a duration flag.
        # Terminating tshark with SIGTERM causes it to not flush the pcap file.

    def _safe_stop(self):
        self._stop_event.set()
        try:
            if self._capture and hasattr(self._capture, "terminate"):
                self._capture.terminate()
        except Exception:
            pass

    def stop_capture(self):
        """Stop capture immediately."""
        self._safe_stop()
        print("[*] Capture stop requested.")

    @staticmethod
    def _get_sniff_time(pkt):
        """Safely extract sniff_time, handling ISO and epoch formats."""
        try:
            return pkt.sniff_time
        except (ValueError, TypeError):
            # Fallback: parse sniff_timestamp manually
            raw = str(getattr(pkt, "sniff_timestamp", ""))
            for fmt in (
                "%Y-%m-%dT%H:%M:%S.%f%z",  # 2026-05-03T14:33:41.383923000Z
                "%Y-%m-%dT%H:%M:%S.%fZ",    # with trailing Z
            ):
                try:
                    clean = raw.replace("Z", "+00:00")
                    return datetime.datetime.fromisoformat(clean)
                except ValueError:
                    continue
            return None

    @staticmethod
    def analyze_pcap(pcap_filename, window_sec=5, model_path=None):
        """Single-pass pcap analysis — returns stats, flow, timeseries, and alerts.

        Much faster than calling get_protocol_stats + get_flow_summary +
        get_protocol_timeseries separately (avoids 3 tshark spawns).
        """
        proto_stats = _init_proto_stats()
        total_packets = 0
        total_bytes = 0
        first_ts = None
        last_ts = None
        timeseries = {}
        epoch0 = None

        try:
            import asyncio
            try:
                asyncio.get_event_loop()
            except RuntimeError:
                asyncio.set_event_loop(asyncio.new_event_loop())

            cap = pyshark.FileCapture(
                pcap_filename,
                tshark_path=_DEFAULT_TSHARK,
            )
            for pkt in cap:
                total_packets += 1
                pkt_size = int(pkt.length)
                total_bytes += pkt_size
                proto_names = {p.layer_name.upper() for p in pkt.layers}

                _count_protocols(proto_names, pkt_size, proto_stats)

                # Timestamps
                ts = TrafficSniffer._get_sniff_time(pkt)
                if ts is not None:
                    try:
                        if isinstance(ts, datetime.datetime):
                            ts_epoch = ts.timestamp()
                        else:
                            ts_epoch = float(ts)
                        if first_ts is None:
                            first_ts = ts_epoch
                        last_ts = ts_epoch
                        rel = ts_epoch - (epoch0 if epoch0 else ts_epoch)
                        if epoch0 is None:
                            epoch0 = ts_epoch
                            rel = 0
                        bucket = int(rel // window_sec) * window_sec
                        if bucket not in timeseries:
                            # Generate real ISO timestamp
                            bucket_time = datetime.datetime.fromtimestamp(
                                epoch0 + bucket, tz=datetime.timezone.utc
                            ).strftime('%Y-%m-%dT%H:%M:%S')
                            timeseries[bucket] = {
                                'time': bucket_time,
                                'HTTP': 0, 'DNS': 0, 'TCP': 0, 'UDP': 0, 'ICMP': 0,
                            }
                        _count_timeseries_proto(proto_names, bucket, timeseries)
                    except (ValueError, TypeError):
                        pass
            cap.close()
        except Exception as exc:
            logger.error(f"Single-pass analysis error: {exc}")

        # Compute duration
        duration = 0.0
        if first_ts and last_ts:
            duration = round(abs(last_ts - first_ts), 2)
        avg_size = round(total_bytes / total_packets, 1) if total_packets > 0 else 0.0

        # Format timeseries
        ts_result = []
        for key in sorted(timeseries):
            ts_result.append(timeseries[key])

        # Per-protocol counts for pie chart
        proto_counts = {p: d['packets'] for p, d in proto_stats.items() if d['packets'] > 0}

        return {
            'stats': proto_counts,
            'summary': {
                'total_packets': total_packets,
                'total_bytes': total_bytes,
                'duration_sec': duration,
                'avg_packet_size': avg_size,
            },
            'time_series': ts_result,
        }

    @staticmethod
    def get_protocol_stats(pcap_filename):
        """Read a pcap file and count packets + bytes per protocol."""
        stats = _init_proto_stats()
        try:
            cap = pyshark.FileCapture(
                pcap_filename,
                tshark_path=_DEFAULT_TSHARK,
            )
            for pkt in cap:
                pkt_size = int(pkt.length)
                proto_names = {p.layer_name.upper() for p in pkt.layers}
                _count_protocols(proto_names, pkt_size, stats)
            cap.close()
        except Exception as exc:
            logger.error(f"Error reading pcap: {exc}")
        return stats

    @staticmethod
    def get_flow_summary(pcap_filename):
        """Return overall flow statistics for a pcap file."""
        summary = {
            'total_packets': 0, 'total_bytes': 0,
            'duration_sec': 0.0, 'avg_packet_size': 0.0,
        }
        try:
            cap = pyshark.FileCapture(
                pcap_filename,
                tshark_path=_DEFAULT_TSHARK,
            )
            pkt_count = 0
            byte_count = 0
            first_ts = None
            last_ts = None
            for pkt in cap:
                pkt_count += 1
                pkt_size = int(pkt.length)
                byte_count += pkt_size
                ts = TrafficSniffer._get_sniff_time(pkt)
                if ts:
                    if first_ts is None:
                        first_ts = ts
                    last_ts = ts
            cap.close()
            duration = 0.0
            if first_ts and last_ts and isinstance(first_ts, datetime.datetime):
                duration = (last_ts - first_ts).total_seconds()
            elif first_ts and last_ts:
                duration = abs(float(last_ts) - float(first_ts))
            avg_size = byte_count / pkt_count if pkt_count > 0 else 0.0
            summary = {
                'total_packets': pkt_count,
                'total_bytes': byte_count,
                'duration_sec': round(duration, 2),
                'avg_packet_size': round(avg_size, 2),
            }
        except Exception as exc:
            print(f"[!] Error: {exc}")
        return summary

    @staticmethod
    def get_protocol_timeseries(pcap_filename, window_sec=5):
        """Binned protocol distribution for time-series charts.

        Groups packets into window_sec-second buckets and counts
        per-protocol packet density in each bucket.

        Returns:
            list[dict] sorted by time, e.g.:
            [{"time":"00:00:05","HTTP":10,"DNS":5,"TCP":30,...}, ...]
        """
        timeseries = {}
        epoch0 = None
        try:
            cap = pyshark.FileCapture(
                pcap_filename,
                tshark_path=_DEFAULT_TSHARK,
            )
            for pkt in cap:
                ts = TrafficSniffer._get_sniff_time(pkt)
                if ts is None:
                    continue
                try:
                    if isinstance(ts, datetime.datetime):
                        ts_epoch = ts.timestamp()
                    else:
                        ts_epoch = float(ts)
                    if epoch0 is None:
                        epoch0 = ts_epoch
                    rel = ts_epoch - epoch0
                    bucket = int(rel // window_sec) * window_sec
                except (ValueError, TypeError):
                    continue
                if bucket not in timeseries:
                    bucket_time = datetime.datetime.fromtimestamp(
                        epoch0 + bucket, tz=datetime.timezone.utc
                    ).strftime('%Y-%m-%dT%H:%M:%S')
                    timeseries[bucket] = {
                        'time': bucket_time,
                        'HTTP': 0, 'DNS': 0, 'TCP': 0, 'UDP': 0, 'ICMP': 0,
                    }
                proto_names = {p.layer_name.upper() for p in pkt.layers}
                _count_timeseries_proto(proto_names, bucket, timeseries)
            cap.close()
        except Exception as exc:
            logger.error(f"Error reading pcap: {exc}")
        result = []
        for key in sorted(timeseries):
            result.append(timeseries[key])
        return result


if __name__ == '__main__':
    import sys

    outfile = sys.argv[1] if len(sys.argv) > 1 else "traffic_test.pcap"
    dur = int(sys.argv[2]) if len(sys.argv) > 2 else 60

    sniffer = TrafficSniffer(interface=None, timeout=dur)
    sniffer.start_capture(outfile)
    sniffer._stop_event.wait()

    print("\n=== Protocol Statistics ===")
    stats = TrafficSniffer.get_protocol_stats(outfile)
    for proto, data in stats.items():
        print(f"  {proto:8s}  packets={data['packets']:>6d}  bytes={data['bytes']:>10d}")

    print("\n=== Flow Summary ===")
    flow = TrafficSniffer.get_flow_summary(outfile)
    for k, v in flow.items():
        print(f"  {k}: {v}")

    print("\n=== Protocol Time Series (5-sec bins) ===")
    ts = TrafficSniffer.get_protocol_timeseries(outfile, window_sec=5)
    for entry in ts:
        print(f"  {entry}")
