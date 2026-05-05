"""
ThreatSight — Flask REST API

Endpoints:
  GET  /                    — service info
  GET  /api/health          — health check
  POST /api/capture         — start background capture
  POST /api/capture/stop    — manual stop
  GET  /api/analyze/<pcap>  — run full analysis
  GET  /api/stats           — last analysis summary
  GET  /api/alerts          — alert list (optional ?severity=high|medium|low)
  GET  /api/scans           — paginated scan history
  GET  /api/scans/<id>      — scan detail with alerts
  GET  /api/config          — read configuration
  POST /api/config          — update configuration
"""

import os
import json
import asyncio
import threading
import datetime

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from flasgger import Swagger

load_dotenv()

import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sniffer import TrafficSniffer
from rule_detector import detect_all
from feature_extractor import FeatureExtractor
from ml_detector import MLAnomalyDetector

app = Flask(__name__)
CORS(app)
swagger = Swagger(app)

DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() in ("true", "1")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CAPTURE_DIR = os.path.join(BASE_DIR, "captures")
RESULTS_DIR = os.path.join(BASE_DIR, "results")
MODEL_PATH = os.path.join(BASE_DIR, "model.pkl")
DB_PATH = os.path.join(BASE_DIR, "threatsight.db")
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")


def load_config():
    """Read config.json and return as dict."""
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _validate_config(data):
    """Validate config dict; return error string or None."""
    # syn_flood
    sf = data.get("syn_flood", {})
    for key in ("threshold",):
        val = sf.get(key)
        if val is not None and not (0 <= val <= 1):
            return f"syn_flood.{key} must be between 0 and 1, got {val}"
    for key in ("window", "min_packets"):
        val = sf.get(key)
        if val is not None and val <= 0:
            return f"syn_flood.{key} must be positive, got {val}"
    # dns_tunnel
    dt = data.get("dns_tunnel", {})
    for key in ("window", "query_threshold", "length_threshold"):
        val = dt.get(key)
        if val is not None and val <= 0:
            return f"dns_tunnel.{key} must be positive, got {val}"
    # port_scan
    ps = data.get("port_scan", {})
    for key in ("window", "port_threshold"):
        val = ps.get(key)
        if val is not None and val <= 0:
            return f"port_scan.{key} must be positive, got {val}"
    # ml
    ml = data.get("ml", {})
    val = ml.get("contamination")
    if val is not None and not (0 < val < 1):
        return f"ml.contamination must be between 0 and 1, got {val}"
    return None

os.makedirs(CAPTURE_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

# ─── SQLAlchemy ──────────────────────────────────────────────────────

app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


class ScanRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    total_packets = db.Column(db.Integer)
    total_bytes = db.Column(db.Integer)
    duration = db.Column(db.Float)
    alert_count = db.Column(db.Integer)
    rule_alert_count = db.Column(db.Integer)
    ml_alert_count = db.Column(db.Integer)
    protocol_stats_json = db.Column(db.Text)  # JSON string
    alerts = db.relationship("Alert", backref="scan", lazy=True)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "duration": self.duration,
            "alert_count": self.alert_count,
            "rule_alert_count": self.rule_alert_count,
            "ml_alert_count": self.ml_alert_count,
            "protocol_stats": json.loads(self.protocol_stats_json) if self.protocol_stats_json else {},
        }


class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan_record.id"))
    timestamp = db.Column(db.String(50))
    type = db.Column(db.String(50))
    severity = db.Column(db.String(20))
    source_ip = db.Column(db.String(45))
    detail = db.Column(db.Text)

    def to_dict(self):
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "type": self.type,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "detail": self.detail,
        }


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
    """
    Service information
    ---
    tags:
      - System
    responses:
      200:
        description: Service info
        examples:
          application/json: {"service": "ThreatSight", "version": "1.0", "demo_mode": false}
    """
    return jsonify({"service": "ThreatSight", "version": "1.0", "demo_mode": DEMO_MODE})


@app.route("/api/health")
def health():
    """
    Health check
    ---
    tags:
      - System
    responses:
      200:
        description: Service health status
        examples:
          application/json: {"status": "ok", "service": "ThreatSight", "demo_mode": false}
    """
    return jsonify({"status": "ok", "service": "ThreatSight", "demo_mode": DEMO_MODE})


@app.route("/api/capture/stop", methods=["POST"])
def stop_capture():
    """
    Manually stop an in-progress capture
    ---
    tags:
      - Capture
    responses:
      200:
        description: Capture stopped
        examples:
          application/json: {"status": "stopped"}
    """
    _state["capture_running"] = False
    try:
        import subprocess
        subprocess.run(["taskkill", "/F", "/IM", "tshark.exe"],
                       capture_output=True, timeout=5)
    except Exception:
        pass
    return jsonify({"status": "stopped"})


@app.route("/api/capture", methods=["POST"])
def start_capture():
    """
    Start a background packet capture
    ---
    tags:
      - Capture
    parameters:
      - in: body
        name: body
        schema:
          type: object
          properties:
            duration:
              type: integer
              default: 60
              description: Capture duration in seconds
            interface:
              type: string
              description: Network interface name
    responses:
      200:
        description: Capture started
        examples:
          application/json: {"status": "capturing", "pcap_file": "captures/capture_xxx.pcap", "duration": 60}
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
        sniffer._stop_event.wait(timeout=duration + 10)
        sniffer.stop_capture()
        _state["capture_running"] = False
        _state["capture_pcap"] = pcap_file

    threading.Thread(target=_run, daemon=True).start()

    return jsonify({
        "status": "capturing",
        "pcap_file": pcap_file,
        "duration": duration,
    })


@app.route("/api/analyze/<path:pcap_filename>")
def analyze(pcap_filename):
    """
    Run rule + ML detection on a pcap file and persist to SQLite
    ---
    tags:
      - Analysis
    parameters:
      - name: pcap_filename
        in: path
        type: string
        required: true
        description: Pcap file name (relative to captures/) or absolute path
    responses:
      200:
        description: Analysis result
      404:
        description: File not found
      500:
        description: Analysis error
    """
    pcap_path = pcap_filename if os.path.isabs(pcap_filename) else os.path.join(CAPTURE_DIR, pcap_filename)
    if not os.path.exists(pcap_path):
        return jsonify({"error": f"File not found: {pcap_filename}"}), 404

    import time
    for _ in range(10):
        if not _state["capture_running"]:
            break
        time.sleep(0.5)

    try:
        # Ensure asyncio event loop for this thread
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        analysis = TrafficSniffer.analyze_pcap(pcap_path, window_sec=5)
        proto_counts = analysis["stats"]
        ts_data = analysis["time_series"]
        flow = analysis["summary"]

        rule_alerts = detect_all(pcap_path)

        fe = FeatureExtractor(window_size=5)
        X = fe.extract(pcap_path)
        feature_names = fe.get_feature_names()
        ml_alerts = []
        if X.shape[0] >= 5 and os.path.exists(MODEL_PATH):
            scores, is_anom = MLAnomalyDetector.predict(X, MODEL_PATH)
            timestamps = [entry.get("time", "") for entry in ts_data]
            while len(timestamps) < len(scores):
                timestamps.append(f"window_{len(timestamps)}")
            ml_alerts = MLAnomalyDetector.generate_alerts(
                timestamps, is_anom, scores, X, feature_names)

        all_alerts = rule_alerts + ml_alerts
        all_alerts.sort(key=lambda a: a.get("timestamp", ""))

        result = {
            "summary": flow,
            "protocol_stats": proto_counts,
            "time_series": ts_data,
            "alerts": all_alerts,
            "alert_count": len(all_alerts),
            "rule_alert_count": len(rule_alerts),
            "ml_alert_count": len(ml_alerts),
        }

        _state["last_result"] = result

        # ─── Persist to SQLite ───────────────────────────────────────
        scan = ScanRecord(
            total_packets=flow.get("total_packets", 0),
            total_bytes=flow.get("total_bytes", 0),
            duration=flow.get("duration", 0),
            alert_count=len(all_alerts),
            rule_alert_count=len(rule_alerts),
            ml_alert_count=len(ml_alerts),
            protocol_stats_json=json.dumps(proto_counts, ensure_ascii=False),
        )
        db.session.add(scan)
        db.session.flush()  # get scan.id

        for a in all_alerts:
            alert = Alert(
                scan_id=scan.id,
                timestamp=str(a.get("timestamp", "")),
                type=a.get("type", ""),
                severity=a.get("severity", ""),
                source_ip=a.get("source_ip", ""),
                detail=a.get("detail", ""),
            )
            db.session.add(alert)

        db.session.commit()
        result["scan_id"] = scan.id
        # ────────────────────────────────────────────────────────────

        # save JSON
        ts_tag = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = os.path.join(RESULTS_DIR, f"result_{ts_tag}.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False, default=str)

        return jsonify(result)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/api/stats")
def stats():
    """
    Return last analysis summary for dashboard polling
    ---
    tags:
      - Analysis
    responses:
      200:
        description: Analysis summary
        examples:
          application/json: {"status": "ok", "summary": {}, "alert_count": 5}
    """
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
    """
    Return all alerts with optional filters
    ---
    tags:
      - Alerts
    parameters:
      - name: severity
        in: query
        type: string
        enum: [high, medium, low]
        description: Filter by severity
      - name: type
        in: query
        type: string
        description: Filter by alert type
      - name: page
        in: query
        type: integer
        default: 1
      - name: per_page
        in: query
        type: integer
        default: 20
    responses:
      200:
        description: Paginated alert list
    """
    severity = request.args.get("severity")
    alert_type = request.args.get("type")
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)

    query = Alert.query
    if severity:
        query = query.filter_by(severity=severity)
    if alert_type:
        query = query.filter_by(type=alert_type)

    pagination = query.order_by(Alert.id.desc()).paginate(page=page, per_page=per_page, error_out=False)
    return jsonify({
        "alerts": [a.to_dict() for a in pagination.items],
        "total": pagination.total,
        "page": page,
        "per_page": per_page,
    })


# ─── Scan History API ───────────────────────────────────────────────

@app.route("/api/scans")
def list_scans():
    """
    Paginated scan history
    ---
    tags:
      - Scans
    parameters:
      - name: page
        in: query
        type: integer
        default: 1
      - name: per_page
        in: query
        type: integer
        default: 20
    responses:
      200:
        description: Paginated scan list
    """
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)

    pagination = ScanRecord.query.order_by(ScanRecord.id.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    return jsonify({
        "scans": [s.to_dict() for s in pagination.items],
        "total": pagination.total,
        "page": page,
        "per_page": per_page,
    })


@app.route("/api/scans/<int:scan_id>")
def get_scan(scan_id):
    """
    Single scan detail with full alert list
    ---
    tags:
      - Scans
    parameters:
      - name: scan_id
        in: path
        type: integer
        required: true
    responses:
      200:
        description: Scan detail with alerts
      404:
        description: Scan not found
    """
    scan = ScanRecord.query.get_or_404(scan_id)
    alert_list = Alert.query.filter_by(scan_id=scan_id).all()
    return jsonify({
        "scan": scan.to_dict(),
        "alerts": [a.to_dict() for a in alert_list],
    })


# ─── Config API ────────────────────────────────────────────────────

@app.route("/api/config", methods=["GET"])
def get_config():
    """
    Read config.json and return it
    ---
    tags:
      - Config
    responses:
      200:
        description: Current configuration
      500:
        description: Config read error
    """
    try:
        cfg = load_config()
        return jsonify(cfg)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/config", methods=["POST"])
def set_config():
    """
    Update config.json with validated payload (partial merge)
    ---
    tags:
      - Config
    parameters:
      - in: body
        name: body
        schema:
          type: object
          properties:
            syn_flood:
              type: object
            dns_tunnel:
              type: object
            port_scan:
              type: object
            ml:
              type: object
    responses:
      200:
        description: Config updated
      400:
        description: Validation error
    """
    data = request.get_json(silent=True) or {}
    err = _validate_config(data)
    if err:
        return jsonify({"error": err}), 400
    try:
        current = load_config()
        # deep merge: only overwrite keys present in payload
        for section, values in data.items():
            if isinstance(values, dict) and section in current:
                current[section].update(values)
            else:
                current[section] = values
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(current, f, indent=2, ensure_ascii=False)
        return jsonify({"status": "ok", "config": current})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/demo/status")
def demo_status():
    """
    Demo mode status
    ---
    tags:
      - Demo
    responses:
      200:
        description: Demo mode info
        examples:
          application/json: {"demo_mode": true, "data_loaded": true, "sample_file": "samples/demo.pcap"}
    """
    sample = os.path.join(BASE_DIR, "samples", "demo.pcap")
    return jsonify({
        "demo_mode": DEMO_MODE,
        "data_loaded": _state["last_result"] is not None,
        "sample_file": "samples/demo.pcap" if os.path.exists(sample) else None,
    })


# ─── main ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    # ── Demo mode: auto-load sample data ─────────────────────────
    if DEMO_MODE:
        demo_pcap = os.path.join(BASE_DIR, "samples", "demo.pcap")
        if os.path.exists(demo_pcap):
            print("[*] Demo mode enabled — analyzing samples/demo.pcap ...")
            try:
                # Ensure asyncio event loop
                try:
                    asyncio.get_running_loop()
                except RuntimeError:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)

                analysis = TrafficSniffer.analyze_pcap(demo_pcap, window_sec=5)
                proto_counts = analysis["stats"]
                ts_data = analysis["time_series"]
                flow = analysis["summary"]

                rule_alerts = detect_all(demo_pcap)
                fe = FeatureExtractor(window_size=5)
                X = fe.extract(demo_pcap)
                feature_names = fe.get_feature_names()
                ml_alerts = []
                if X.shape[0] >= 5 and os.path.exists(MODEL_PATH):
                    scores, is_anom = MLAnomalyDetector.predict(X, MODEL_PATH)
                    timestamps = [entry.get("time", "") for entry in ts_data]
                    while len(timestamps) < len(scores):
                        timestamps.append(f"window_{len(timestamps)}")
                    ml_alerts = MLAnomalyDetector.generate_alerts(
                        timestamps, is_anom, scores, X, feature_names)

                all_alerts = rule_alerts + ml_alerts
                all_alerts.sort(key=lambda a: a.get("timestamp", ""))

                result = {
                    "summary": flow,
                    "protocol_stats": proto_counts,
                    "time_series": ts_data,
                    "alerts": all_alerts,
                    "alert_count": len(all_alerts),
                    "rule_alert_count": len(rule_alerts),
                    "ml_alert_count": len(ml_alerts),
                }
                _state["last_result"] = result

                with app.app_context():
                    scan = ScanRecord(
                        total_packets=flow.get("total_packets", 0),
                        total_bytes=flow.get("total_bytes", 0),
                        duration=flow.get("duration", 0),
                        alert_count=len(all_alerts),
                        rule_alert_count=len(rule_alerts),
                        ml_alert_count=len(ml_alerts),
                        protocol_stats_json=json.dumps(proto_counts, ensure_ascii=False),
                    )
                    db.session.add(scan)
                    db.session.flush()
                    for a in all_alerts:
                        alert = Alert(
                            scan_id=scan.id,
                            timestamp=str(a.get("timestamp", "")),
                            type=a.get("type", ""),
                            severity=a.get("severity", ""),
                            source_ip=a.get("source_ip", ""),
                            detail=a.get("detail", ""),
                        )
                        db.session.add(alert)
                    db.session.commit()
                    result["scan_id"] = scan.id

                # Save demo result JSON
                os.makedirs(RESULTS_DIR, exist_ok=True)
                demo_json = os.path.join(RESULTS_DIR, "demo_result.json")
                with open(demo_json, "w", encoding="utf-8") as f:
                    json.dump(result, f, indent=2, ensure_ascii=False, default=str)

                print(f"[*] Demo mode enabled. Demo data loaded. ({len(all_alerts)} alerts, scan_id={scan.id})")
            except Exception as e:
                print(f"[!] Demo data load failed: {e}")
        else:
            print(f"[!] DEMO_MODE=true but {demo_pcap} not found")

    mode_tag = " [DEMO]" if DEMO_MODE else ""
    print(f"[*] ThreatSight API starting on port 5000{mode_tag}")
    print(f"[*] SQLite database: {DB_PATH}")
    print(f"[*] Swagger UI: http://localhost:5000/apidocs")
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
