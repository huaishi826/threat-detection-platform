"""
Flask REST API for Threat Detection Platform.

Endpoints:
  GET  /                    — service info
  POST /api/capture         — start background capture
  GET  /api/analyze/<pcap>  — run full analysis
  GET  /api/stats           — last analysis summary
  GET  /api/alerts          — alert list (optional ?severity=high|medium|low)
"""

import os
import json
import threading
import datetime

from flask import Flask, request, jsonify
from flask_cors import CORS

import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sniffer import TrafficSniffer
from rule_detector import detect_all
from feature_extractor import FeatureExtractor
from ml_detector import MLAnomalyDetector

app = Flask(__name__)
CORS(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CAPTURE_DIR = os.path.join(BASE_DIR, "captures")
RESULTS_DIR = os.path.join(BASE_DIR, "results")
MODEL_PATH = os.path.join(BASE_DIR, "model.pkl")

os.makedirs(CAPTURE_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

# shared state (single-user demo)
_state = {
    "last_result": None,
    "capture_running": False,
    "capture_progress": 0,
    "capture_total": 0,
}


# ─── API ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return jsonify({"service": "Threat Detection Platform", "version": "1.0"})


@app.route("/api/capture", methods=["POST"])
def start_capture():
    """Start a background packet capture.

    Request JSON:
        {"duration": 60, "interface": null}
    """
    data = request.get_json(silent=True) or {}
    duration = int(data.get("duration", 60))
    interface = data.get("interface", None)

    ts_tag = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_file = os.path.join(CAPTURE_DIR, f"capture_{ts_tag}.pcap")

    _state["capture_running"] = True
    _state["capture_progress"] = 0
    _state["capture_total"] = duration

    def _run():
        sniffer = TrafficSniffer(interface=interface, timeout=duration)
        sniffer.start_capture(pcap_file)
        sniffer._stop_event.wait()
        _state["capture_running"] = False

    threading.Thread(target=_run, daemon=True).start()

    return jsonify({
        "status": "capturing",
        "pcap_file": pcap_file,
        "duration": duration,
    })


@app.route("/api/analyze/<pcap_filename>")
def analyze(pcap_filename):
    """Run rule + ML detection on a pcap file."""
    pcap_path = os.path.join(CAPTURE_DIR, pcap_filename)
    if not os.path.exists(pcap_path):
        return jsonify({"error": f"File not found: {pcap_filename}"}), 404

    try:
        # protocol stats
        stats = TrafficSniffer.get_protocol_stats(pcap_path)
        flow = TrafficSniffer.get_flow_summary(pcap_path)

        # rule detection
        rule_alerts = detect_all(pcap_path)

        # ML detection
        fe = FeatureExtractor(window_size=5)
        X = fe.extract(pcap_path)
        feature_names = fe.get_feature_names()
        ml_alerts = []
        if X.shape[0] >= 5 and os.path.exists(MODEL_PATH):
            scores, is_anom = MLAnomalyDetector.predict(X, MODEL_PATH)
            timestamps = []
            ts_data = TrafficSniffer.get_protocol_timeseries(pcap_path, window_sec=5)
            for entry in ts_data:
                timestamps.append(entry.get("time", ""))
            while len(timestamps) < len(scores):
                timestamps.append(f"window_{len(timestamps)}")
            ml_alerts = MLAnomalyDetector.generate_alerts(
                timestamps, is_anom, scores, X, feature_names)

        all_alerts = rule_alerts + ml_alerts
        all_alerts.sort(key=lambda a: a.get("timestamp", ""))

        # per-protocol packet counts for pie chart
        proto_counts = {p: d["packets"] for p, d in stats.items() if d["packets"] > 0}

        result = {
            "summary": {
                "total_packets": flow["total_packets"],
                "total_bytes": flow["total_bytes"],
                "duration_sec": flow["duration_sec"],
                "avg_packet_size": round(
                    flow["total_bytes"] / flow["total_packets"], 1)
                if flow["total_packets"] > 0 else 0,
            },
            "protocol_stats": proto_counts,
            "alerts": all_alerts,
            "alert_count": len(all_alerts),
            "rule_alert_count": len(rule_alerts),
            "ml_alert_count": len(ml_alerts),
        }

        _state["last_result"] = result

        # save JSON
        ts_tag = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = os.path.join(RESULTS_DIR, f"result_{ts_tag}.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False, default=str)

        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/stats")
def stats():
    """Return last analysis summary for dashboard polling."""
    if _state["last_result"] is None:
        return jsonify({"status": "no_data"})
    r = _state["last_result"]
    return jsonify({
        "status": "ok",
        "summary": r["summary"],
        "alert_count": r["alert_count"],
        "rule_alert_count": r["rule_alert_count"],
        "ml_alert_count": r["ml_alert_count"],
        "protocol_stats": r["protocol_stats"],
        "capture_running": _state["capture_running"],
    })


@app.route("/api/alerts")
def alerts():
    """Return alert list, optionally filtered by ?severity=."""
    if _state["last_result"] is None:
        return jsonify({"alerts": [], "total": 0})

    alert_list = _state["last_result"]["alerts"]
    severity = request.args.get("severity")
    if severity:
        alert_list = [a for a in alert_list if a.get("severity") == severity]

    return jsonify({"alerts": alert_list, "total": len(alert_list)})


# ─── main ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("[*] Starting Threat Detection Platform API on port 5000")
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
