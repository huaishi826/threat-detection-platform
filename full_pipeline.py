"""
Full-pipeline integration: capture -> rule detect -> ML detect -> JSON report.

Usage:
    python full_pipeline.py [duration_sec]

Flow:
  1. Start TrafficSniffer background capture
  2. Wait for user to run attack_simulator.py in another terminal
  3. Analyse captured pcap with all detection modules
  4. Print human-readable report
  5. Save result_YYYYMMDD_HHMMSS.json
"""

import sys
import os
import json
import datetime
import tempfile
import time

# ensure project root on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sniffer import TrafficSniffer
from rule_detector import detect_all
from feature_extractor import FeatureExtractor
from ml_detector import MLAnomalyDetector

from pathlib import Path


def run_pipeline(duration=60):
    """Execute full capture + analysis pipeline.

    Args:
        duration: Capture window in seconds.
    """
    tmp_dir = tempfile.mkdtemp(prefix="pipeline_")
    pcap_path = os.path.join(tmp_dir, "capture.pcap")
    model_path = "model.pkl"

    # ── 1. capture ──────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  Full Pipeline Test")
    print(f"{'='*60}")
    print(f"  Duration: {duration}s")
    print(f"  PCAP:     {pcap_path}\n")

    sniffer = TrafficSniffer(interface=None, timeout=duration)
    sniffer.start_capture(pcap_path)

    print(f"[*] Capturing for {duration}s ...")
    print(f"    ⚡ Open another terminal and run attack_simulator.py NOW!\n")

    # show countdown
    for remaining in range(duration, 0, -1):
        print(f"\r    ⏳ {remaining}s remaining ", end="", flush=True)
        time.sleep(1)
    print()

    sniffer._stop_event.wait()

    # ── 2. protocol stats ───────────────────────────────────────────
    print(f"\n{'─'*60}")
    print("  Protocol Statistics")
    print(f"{'─'*60}")

    stats = TrafficSniffer.get_protocol_stats(pcap_path)
    flow = TrafficSniffer.get_flow_summary(pcap_path)

    # sort by packets desc, show top 5
    sorted_proto = sorted(
        stats.items(), key=lambda x: x[1]["packets"], reverse=True)
    top5 = [(p, d) for p, d in sorted_proto if d["packets"] > 0][:5]

    for proto, data in top5:
        print(f"  {proto:8s}  packets={data['packets']:>7d}  "
              f"bytes={data['bytes']:>10d}")

    print(f"\n  Total: {flow['total_packets']} pkts / "
          f"{flow['total_bytes']} bytes / {flow['duration_sec']}s")

    # ── 3. rule detection ───────────────────────────────────────────
    print(f"\n{'─'*60}")
    print("  Rule Detection")
    print(f"{'─'*60}")

    rule_alerts = detect_all(pcap_path)
    if rule_alerts:
        print(f"  {len(rule_alerts)} rule alert(s):\n")
        for a in rule_alerts:
            print(f"  [{a['severity'].upper():6s}] {a['type']:15s}  "
                  f"{a['timestamp']}  src={a['source_ip']}")
            print(f"         {a['detail']}\n")
    else:
        print("  No rule alerts.")

    # ── 4. ML detection ─────────────────────────────────────────────
    print(f"\n{'─'*60}")
    print("  ML Anomaly Detection")
    print(f"{'─'*60}")

    fe = FeatureExtractor(window_size=5)
    X = fe.extract(pcap_path)
    feature_names = fe.get_feature_names()

    ml_alerts = []
    if X.shape[0] < 5:
        print(f"  Only {X.shape[0]} windows (need >= 5) -- skipping ML.")
    else:
        if not Path(model_path).exists():
            print(f"  Training model from captured data ...")
            det = MLAnomalyDetector()
            det.train(X, model_path)

        scores, is_anom = MLAnomalyDetector.predict(X, model_path)
        timestamps = []
        # try to reconstruct timestamps from pcap
        ts_data = TrafficSniffer.get_protocol_timeseries(pcap_path, window_sec=5)
        for entry in ts_data:
            timestamps.append(entry.get("time", ""))
        # pad if needed
        while len(timestamps) < len(scores):
            timestamps.append(f"window_{len(timestamps)}")

        ml_alerts = MLAnomalyDetector.generate_alerts(
            timestamps, is_anom, scores, X, feature_names)

        print(f"  Windows:       {len(scores)}")
        print(f"  Anomalies:     {is_anom.sum()}")
        print(f"  Anomaly ratio: {is_anom.mean():.1%}\n")

        if ml_alerts:
            for a in ml_alerts:
                print(f"  [{a['severity'].upper():6s}] score={a['anomaly_score']}")
                print(f"         {a['detail']}\n")
        else:
            print("  No ML anomalies.")

    # ── 5. JSON report ──────────────────────────────────────────────
    all_alerts = rule_alerts + ml_alerts
    all_alerts.sort(key=lambda a: a.get("timestamp", ""))

    report = {
        "timestamp": datetime.datetime.now().isoformat(),
        "summary": {
            "duration_sec": flow["duration_sec"],
            "total_packets": flow["total_packets"],
            "total_bytes": flow["total_bytes"],
            "rule_alerts": len(rule_alerts),
            "ml_alerts": len(ml_alerts),
            "total_alerts": len(all_alerts),
        },
        "protocol_stats": {p: d for p, d in stats.items() if d["packets"] > 0},
        "flow_summary": flow,
        "alerts": all_alerts,
    }

    ts_tag = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = f"result_{ts_tag}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)

    # ── summary ─────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  SUMMARY")
    print(f"{'='*60}")
    print(f"  Packets:     {flow['total_packets']}")
    print(f"  Duration:    {flow['duration_sec']}s")
    print(f"  Rule alerts: {len(rule_alerts)}")
    print(f"  ML alerts:   {len(ml_alerts)}")
    print(f"  JSON report: {json_path}")
    print(f"{'='*60}\n")

    return report


# ─── main ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    dur = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    run_pipeline(dur)
