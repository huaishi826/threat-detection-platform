import tempfile, os, datetime, subprocess, threading
import pyshark


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

    def __init__(self, interface=None, timeout=60):
        self.interface = interface
        self.timeout = timeout
        self._capture = None
        self._stop_event = threading.Event()
        self._tshark = r"C:\Program Files\Wireshark\tshark.exe"

    # ── capture helpers ────────────────────────────────────────────

    def _auto_interface(self):
        """Return first available non-loopback interface via tshark -D."""
        try:
            result = subprocess.run(
                [self._tshark, "-D"],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.splitlines():
                parts = line.split(".", 1)
                if len(parts) == 2:
                    name = parts[1].strip()
                    if "loopback" not in name.lower():
                        return name
        except Exception:
            pass
        return "eth0"  # safe fallback

    def start_capture(self, pcap_filename):
        """Start live capture on background thread.

        Packets are saved to *pcap_filename*.  Capture stops
        automatically after *self.timeout* seconds or when
        stop_capture() is called.

        Args:
            pcap_filename: Output .pcap file path.
        """
        iface = self.interface or self._auto_interface()
        print(f"[*] Starting capture on '{iface}' for {self.timeout}s ...")
        print(f"    Output: {pcap_filename}")

        self._stop_event.clear()

        def _run():
            try:
                self._capture = pyshark.LiveCapture(
                    interface=iface,
                    output_file=pcap_filename,
                    tshark_path=self._tshark,
                )
                # Blocking iterator -- stops when _stop_event is set
                for pkt in self._capture.sniff_continuously():
                    if self._stop_event.is_set():
                        break
            except PermissionError:
                print("[!] Permission denied.  Run as Administrator.")
            except Exception as exc:
                if not self._stop_event.is_set():
                    print(f"[!] Capture error: {exc}")
            finally:
                try:
                    self._capture.close()
                except Exception:
                    pass
                print("[*] Capture finished.")

        t = threading.Thread(target=_run, daemon=True)
        t.start()

        if self.timeout > 0:
            threading.Timer(self.timeout, self._safe_stop).start()

    def _safe_stop(self):
        self._stop_event.set()

    def stop_capture(self):
        """Stop capture immediately."""
        self._safe_stop()
        print("[*] Capture stop requested.")

    # ── static analysis ────────────────────────────────────────────

    @staticmethod
    def get_protocol_stats(pcap_filename):
        """Read a pcap file and count packets + bytes per protocol.

        Args:
            pcap_filename: Path to .pcap file.

        Returns:
            dict  e.g. {"HTTP": {"packets": 10, "bytes": 4096}, ...}
        """
        stats = {
            'HTTP':   {'packets': 0, 'bytes': 0},
            'DNS':    {'packets': 0, 'bytes': 0},
            'TCP':    {'packets': 0, 'bytes': 0},
            'UDP':    {'packets': 0, 'bytes': 0},
            'ICMP':   {'packets': 0, 'bytes': 0},
            'TLS/SSL': {'packets': 0, 'bytes': 0},
            'ARP':    {'packets': 0, 'bytes': 0},
        }

        try:
            cap = pyshark.FileCapture(
                pcap_filename, tshark_path=r"C:\Program Files\Wireshark\tshark.exe"
            )
            for pkt in cap:
                pkt_size = int(pkt.length)
                proto_layers = set(pkt.layers)
                proto_names = {p.layer_name.upper() for p in pkt.layers}

                if 'HTTP' in proto_names:
                    stats['HTTP']['packets'] += 1
                    stats['HTTP']['bytes'] += pkt_size
                if 'DNS' in proto_names:
                    stats['DNS']['packets'] += 1
                    stats['DNS']['bytes'] += pkt_size
                if 'TCP' in proto_names:
                    stats['TCP']['packets'] += 1
                    stats['TCP']['bytes'] += pkt_size
                if 'UDP' in proto_names:
                    stats['UDP']['packets'] += 1
                    stats['UDP']['bytes'] += pkt_size
                if 'ICMPV6' in proto_names or 'ICMP' in proto_names:
                    stats['ICMP']['packets'] += 1
                    stats['ICMP']['bytes'] += pkt_size
                if 'TLS' in proto_names or 'SSL' in proto_names:
                    stats['TLS/SSL']['packets'] += 1
                    stats['TLS/SSL']['bytes'] += pkt_size
                if 'ARP' in proto_names:
                    stats['ARP']['packets'] += 1
                    stats['ARP']['bytes'] += pkt_size
            cap.close()
        except Exception as exc:
            print(f"[!] Error reading pcap: {exc}")

        return stats

    @staticmethod
    def get_flow_summary(pcap_filename):
        """Return overall flow statistics for a pcap file.

        Args:
            pcap_filename: Path to .pcap file.

        Returns:
            dict  keys: total_packets, total_bytes, duration_sec, avg_packet_size
        """
        summary = {
            'total_packets':   0,
            'total_bytes':     0,
            'duration_sec':    0.0,
            'avg_packet_size': 0.0,
        }

        try:
            cap = pyshark.FileCapture(
                pcap_filename, tshark_path=r"C:\Program Files\Wireshark\tshark.exe"
            )
            pkt_count = 0
            byte_count = 0
            first_ts = None
            last_ts = None

            for pkt in cap:
                pkt_count += 1
                pkt_size = int(pkt.length)
                byte_count += pkt_size
                try:
                    dt = datetime.datetime.fromisoformat(str(pkt.sniff_time))
                    if first_ts is None:
                        first_ts = dt
                    last_ts = dt
                except Exception:
                    pass

            cap.close()

            duration = 0.0
            if first_ts and last_ts:
                duration = (last_ts - first_ts).total_seconds()
            avg_size = byte_count / pkt_count if pkt_count > 0 else 0.0

            summary = {
                'total_packets':   pkt_count,
                'total_bytes':     byte_count,
                'duration_sec':    round(duration, 2),
                'avg_packet_size': round(avg_size, 2),
            }
        except Exception as exc:
            print(f"[!] Error: {exc}")

        return summary

    @staticmethod
    def get_protocol_timeseries(pcap_filename, window_sec=5):
        """Binned protocol distribution for time-series charts.

        Groups packets into *window_sec*-second buckets and counts
        per-protocol packet density in each bucket.

        Args:
            pcap_filename: Path to .pcap file.
            window_sec:    Bucket width in seconds.

        Returns:
            list[dict]  sorted by time, e.g.:
            [{"time":"00:00:05","HTTP":10,"DNS":5,"TCP":30,...}, ...]
        """
        timeseries = {}
        epoch0 = None

        try:
            cap = pyshark.FileCapture(
                pcap_filename, tshark_path=r"C:\Program Files\Wireshark\tshark.exe"
            )
            for pkt in cap:
                try:
                    dt = datetime.datetime.fromisoformat(str(pkt.sniff_time))
                    ts = dt.timestamp()
                    if epoch0 is None:
                        epoch0 = ts
                    rel = ts - epoch0
                    bucket = int(rel // window_sec) * window_sec
                except Exception:
                    continue

                if bucket not in timeseries:
                    timeseries[bucket] = {
                        'time': datetime.timedelta(seconds=bucket + window_sec),
                        'HTTP': 0, 'DNS': 0, 'TCP': 0, 'UDP': 0, 'ICMP': 0,
                    }

                proto_names = {p.layer_name.upper() for p in pkt.layers}
                if 'HTTP' in proto_names:
                    timeseries[bucket]['HTTP'] += 1
                if 'DNS' in proto_names:
                    timeseries[bucket]['DNS'] += 1
                if 'TCP' in proto_names:
                    timeseries[bucket]['TCP'] += 1
                if 'UDP' in proto_names:
                    timeseries[bucket]['UDP'] += 1
                if 'ICMPV6' in proto_names or 'ICMP' in proto_names:
                    timeseries[bucket]['ICMP'] += 1

            cap.close()
        except Exception as exc:
            print(f"[!] Error: {exc}")

        result = []
        for key in sorted(timeseries):
            entry = timeseries[key]
            entry['time'] = str(entry['time'])
            result.append(entry)

        return result


# ── quick demo ─────────────────────────────────────────────────────

if __name__ == '__main__':
    import sys

    outfile = sys.argv[1] if len(sys.argv) > 1 else "traffic_test.pcap"
    dur = int(sys.argv[2]) if len(sys.argv) > 2 else 60

    sniffer = TrafficSniffer(interface=None, timeout=dur)
    sniffer.start_capture(outfile)
    sniffer._stop_event.wait()  # wait for timeout or manual stop

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
