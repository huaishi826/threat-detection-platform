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

    def _auto_interface(self):
        """Return best available NPF interface via tshark -D.

        Preference order: WLAN / Wi-Fi / Ethernet / 以太网 first,
        then first non-loopback as fallback.
        """
        try:
            result = subprocess.run(
                [self._tshark, "-D"],
                capture_output=True, text=False, timeout=10,
            )
            raw = result.stdout.decode("gbk", errors="replace")
            preferred = ["WLAN", "Wi-Fi", "Ethernet", "以太网", "VMnet1"]
            best = None
            fallback = None
            fallback_name = ""
            for line in raw.splitlines():
                line = line.strip()
                if "\\Device\\NPF_" not in line:
                    continue
                if "Loopback" in line or "etwdump" in line:
                    continue
                start = line.index("\\Device\\NPF_")
                end = line.index(" ", start) if " " in line[start:] else len(line)
                path = line[start:end]
                adapter = line[end:].strip(" ()")
                for kw in preferred:
                    if kw.lower() in adapter.lower():
                        print(f"    Auto-selected preferred: {path} ({adapter})")
                        return path
                if fallback is None:
                    fallback = path
                    fallback_name = adapter
            if fallback:
                print(f"    Auto-selected fallback: {fallback} ({fallback_name})")
                return fallback
        except Exception as exc:
            print(f"    Interface detection failed: {exc}")
        return "\\Device\\NPF_Loopback"

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

        def _run():
            import asyncio
            try:
                asyncio.set_event_loop(asyncio.new_event_loop())
            except Exception:
                pass
            try:
                self._capture = pyshark.LiveCapture(
                    interface=iface,
                    output_file=pcap_filename,
                    tshark_path=self._tshark,
                )
                for pkt in self._capture.sniff_continuously():
                    if self._stop_event.is_set():
                        break
            except PermissionError:
                print("[!] Permission denied. Run as Administrator.")
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
        proto_stats = {
            'HTTP':    {'packets': 0, 'bytes': 0},
            'DNS':     {'packets': 0, 'bytes': 0},
            'TCP':     {'packets': 0, 'bytes': 0},
            'UDP':     {'packets': 0, 'bytes': 0},
            'ICMP':    {'packets': 0, 'bytes': 0},
            'TLS/SSL': {'packets': 0, 'bytes': 0},
            'ARP':     {'packets': 0, 'bytes': 0},
        }
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
                tshark_path=r"C:\Program Files\Wireshark\tshark.exe",
            )
            for pkt in cap:
                total_packets += 1
                pkt_size = int(pkt.length)
                total_bytes += pkt_size
                proto_names = {p.layer_name.upper() for p in pkt.layers}

                # Per-protocol stats
                if 'HTTP' in proto_names:
                    proto_stats['HTTP']['packets'] += 1
                    proto_stats['HTTP']['bytes'] += pkt_size
                if 'DNS' in proto_names:
                    proto_stats['DNS']['packets'] += 1
                    proto_stats['DNS']['bytes'] += pkt_size
                if 'TCP' in proto_names:
                    proto_stats['TCP']['packets'] += 1
                    proto_stats['TCP']['bytes'] += pkt_size
                if 'UDP' in proto_names:
                    proto_stats['UDP']['packets'] += 1
                    proto_stats['UDP']['bytes'] += pkt_size
                if 'ICMPV6' in proto_names or 'ICMP' in proto_names:
                    proto_stats['ICMP']['packets'] += 1
                    proto_stats['ICMP']['bytes'] += pkt_size
                if 'TLS' in proto_names or 'SSL' in proto_names:
                    proto_stats['TLS/SSL']['packets'] += 1
                    proto_stats['TLS/SSL']['bytes'] += pkt_size
                if 'ARP' in proto_names:
                    proto_stats['ARP']['packets'] += 1
                    proto_stats['ARP']['bytes'] += pkt_size

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
                            timeseries[bucket] = {
                                'time': datetime.timedelta(seconds=bucket + window_sec),
                                'HTTP': 0, 'DNS': 0, 'TCP': 0, 'UDP': 0, 'ICMP': 0,
                            }
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
                    except (ValueError, TypeError):
                        pass
            cap.close()
        except Exception as exc:
            print(f"[!] Single-pass analysis error: {exc}")

        # Compute duration
        duration = 0.0
        if first_ts and last_ts:
            duration = round(abs(last_ts - first_ts), 2)
        avg_size = round(total_bytes / total_packets, 1) if total_packets > 0 else 0.0

        # Format timeseries
        ts_result = []
        for key in sorted(timeseries):
            entry = timeseries[key]
            entry['time'] = str(entry['time'])
            ts_result.append(entry)

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
        stats = {
            'HTTP':    {'packets': 0, 'bytes': 0},
            'DNS':     {'packets': 0, 'bytes': 0},
            'TCP':     {'packets': 0, 'bytes': 0},
            'UDP':     {'packets': 0, 'bytes': 0},
            'ICMP':    {'packets': 0, 'bytes': 0},
            'TLS/SSL': {'packets': 0, 'bytes': 0},
            'ARP':     {'packets': 0, 'bytes': 0},
        }
        try:
            cap = pyshark.FileCapture(
                pcap_filename,
                tshark_path=r"C:\Program Files\Wireshark\tshark.exe",
            )
            for pkt in cap:
                pkt_size = int(pkt.length)
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
        """Return overall flow statistics for a pcap file."""
        summary = {
            'total_packets': 0, 'total_bytes': 0,
            'duration_sec': 0.0, 'avg_packet_size': 0.0,
        }
        try:
            cap = pyshark.FileCapture(
                pcap_filename,
                tshark_path=r"C:\Program Files\Wireshark\tshark.exe",
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
                tshark_path=r"C:\Program Files\Wireshark\tshark.exe",
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
