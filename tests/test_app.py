"""Tests for Flask API endpoints in app.py."""

import json
import os
import pytest


class TestHealthEndpoints:
    """Test system endpoints."""

    def test_index(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["service"] == "ThreatSight"
        assert "version" in data

    def test_health(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"

    def test_demo_status(self, client):
        resp = client.get("/api/demo/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "demo_mode" in data


class TestConfigAPI:
    """Test configuration endpoints."""

    def test_get_config(self, client):
        resp = client.get("/api/config")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "syn_flood" in data
        assert "dns_tunnel" in data
        assert "port_scan" in data
        assert "ml" in data

    def test_post_config_valid(self, client):
        payload = {"syn_flood": {"threshold": 0.8}}
        resp = client.post("/api/config", json=payload)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert data["config"]["syn_flood"]["threshold"] == 0.8

    def test_post_config_invalid_threshold(self, client):
        payload = {"syn_flood": {"threshold": 1.5}}
        resp = client.post("/api/config", json=payload)
        assert resp.status_code == 400
        data = resp.get_json()
        assert "error" in data

    def test_post_config_invalid_ml(self, client):
        payload = {"ml": {"contamination": 0}}
        resp = client.post("/api/config", json=payload)
        assert resp.status_code == 400


class TestValidateConfig:
    """Test _validate_config function."""

    def test_valid_config(self):
        from app import _validate_config
        assert _validate_config({"syn_flood": {"threshold": 0.5}}) is None

    def test_threshold_out_of_range(self):
        from app import _validate_config
        err = _validate_config({"syn_flood": {"threshold": 1.5}})
        assert err is not None
        assert "threshold" in err

    def test_negative_window(self):
        from app import _validate_config
        err = _validate_config({"syn_flood": {"window": -1}})
        assert err is not None

    def test_ml_contamination_zero(self):
        from app import _validate_config
        err = _validate_config({"ml": {"contamination": 0}})
        assert err is not None

    def test_ml_contamination_one(self):
        from app import _validate_config
        err = _validate_config({"ml": {"contamination": 1.0}})
        assert err is not None

    def test_empty_config_valid(self):
        from app import _validate_config
        assert _validate_config({}) is None


class TestScanAlertsAPI:
    """Test scan and alert endpoints."""

    def test_scans_empty(self, client):
        resp = client.get("/api/scans")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "scans" in data
        assert "total" in data

    def test_scans_pagination(self, client):
        resp = client.get("/api/scans?page=1&per_page=5")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["per_page"] == 5

    def test_scan_not_found(self, client):
        resp = client.get("/api/scans/99999")
        assert resp.status_code == 404

    def test_alerts_empty(self, client):
        resp = client.get("/api/alerts")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "alerts" in data

    def test_alerts_filter_severity(self, client):
        resp = client.get("/api/alerts?severity=high")
        assert resp.status_code == 200

    def test_stats_no_data(self, client):
        resp = client.get("/api/stats")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] in ("ok", "no_data")


class TestAnalyzeEndpoint:
    """Test /api/analyze endpoint."""

    def test_analyze_path_traversal_blocked(self, client):
        resp = client.get("/api/analyze/../../../etc/passwd")
        assert resp.status_code == 400

    def test_analyze_absolute_path_blocked(self, client):
        resp = client.get("/api/analyze/C:/Windows/System32/config/SAM")
        assert resp.status_code in (400, 404)

    def test_analyze_nonexistent_file(self, client):
        resp = client.get("/api/analyze/nonexistent.pcap")
        assert resp.status_code == 404

    def test_analyze_valid_pcap(self, client, demo_pcap):
        import shutil
        # Copy demo pcap to captures dir for testing
        from app import CAPTURE_DIR
        dest = os.path.join(CAPTURE_DIR, "test_demo.pcap")
        shutil.copy2(demo_pcap, dest)
        try:
            resp = client.get("/api/analyze/test_demo.pcap")
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["status"] == "ok"
            assert "alerts" in data
            assert "summary" in data
        finally:
            os.remove(dest)


class TestModels:
    """Test SQLAlchemy model serialization."""

    def test_scan_record_to_dict(self, app):
        from app import ScanRecord, db
        with app.app_context():
            scan = ScanRecord(
                total_packets=100, total_bytes=5000, duration=10.0,
                alert_count=3, rule_alert_count=2, ml_alert_count=1,
                protocol_stats_json='{"TCP": 80}'
            )
            db.session.add(scan)
            db.session.commit()
            d = scan.to_dict()
            assert d["total_packets"] == 100
            assert d["protocol_stats"] == {"TCP": 80}
            assert "timestamp" in d

    def test_alert_to_dict(self, app):
        from app import Alert, ScanRecord, db
        with app.app_context():
            scan = ScanRecord(total_packets=10, total_bytes=500,
                              duration=1.0, alert_count=1,
                              rule_alert_count=1, ml_alert_count=0,
                              protocol_stats_json='{}')
            db.session.add(scan)
            db.session.flush()
            alert = Alert(scan_id=scan.id, timestamp="2026-01-01T00:00:00",
                          type="SYN_Flood", severity="high",
                          source_ip="10.0.0.1", detail="test")
            db.session.add(alert)
            db.session.commit()
            d = alert.to_dict()
            assert d["type"] == "SYN_Flood"
            assert d["severity"] == "high"
            assert d["source_ip"] == "10.0.0.1"


class TestCaptureEndpoints:
    """Test capture start/stop/progress endpoints."""

    def test_start_capture(self, client):
        resp = client.post("/api/capture", json={"duration": 5})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "capturing"
        assert "pcap_file" in data

    def test_stop_capture(self, client):
        resp = client.post("/api/capture/stop")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "stopped"

    def test_capture_progress(self, client):
        resp = client.get("/api/capture/progress")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "running" in data
        assert "elapsed" in data
        assert "total" in data
        assert "percent" in data


class TestValidateConfigExtended:
    """Extended config validation tests."""

    def test_dns_tunnel_positive_values(self):
        from app import _validate_config
        assert _validate_config({"dns_tunnel": {"window": 30}}) is None

    def test_dns_tunnel_negative(self):
        from app import _validate_config
        err = _validate_config({"dns_tunnel": {"window": -1}})
        assert err is not None

    def test_port_scan_positive(self):
        from app import _validate_config
        assert _validate_config({"port_scan": {"port_threshold": 10}}) is None

    def test_port_scan_negative(self):
        from app import _validate_config
        err = _validate_config({"port_scan": {"port_threshold": 0}})
        assert err is not None

    def test_syn_flood_min_packets_negative(self):
        from app import _validate_config
        err = _validate_config({"syn_flood": {"min_packets": -5}})
        assert err is not None

    def test_ml_contamination_valid(self):
        from app import _validate_config
        assert _validate_config({"ml": {"contamination": 0.1}}) is None

    def test_unknown_section_ignored(self):
        from app import _validate_config
        assert _validate_config({"unknown": {"key": 1}}) is None


class TestErrorHandlers:
    """Test unified error responses."""

    def test_404_returns_json(self, client):
        resp = client.get("/api/nonexistent")
        assert resp.status_code == 404
        data = resp.get_json()
        assert "error" in data
        assert data["code"] == 404

    def test_405_method_not_allowed(self, client):
        resp = client.delete("/api/health")
        assert resp.status_code == 405


class TestModelEdgeCases:
    """Test model serialization edge cases."""

    def test_scan_record_null_protocol_stats(self, app):
        from app import ScanRecord, db
        with app.app_context():
            scan = ScanRecord(total_packets=0, total_bytes=0, duration=0.0,
                              alert_count=0, rule_alert_count=0, ml_alert_count=0,
                              protocol_stats_json=None)
            db.session.add(scan)
            db.session.commit()
            d = scan.to_dict()
            assert d["protocol_stats"] == {}

    def test_alert_timestamp_with_timezone(self, app):
        from app import Alert, ScanRecord, db
        with app.app_context():
            scan = ScanRecord(total_packets=1, total_bytes=50, duration=0.1,
                              alert_count=1, rule_alert_count=1, ml_alert_count=0,
                              protocol_stats_json='{}')
            db.session.add(scan)
            db.session.flush()
            alert = Alert(scan_id=scan.id, timestamp="2026-01-01T00:00:00+00:00",
                          type="DNS_Tunnel", severity="medium",
                          source_ip="10.0.0.2", detail="test")
            db.session.add(alert)
            db.session.commit()
            d = alert.to_dict()
            assert "+00:00" in d["timestamp"] or d["timestamp"] == "2026-01-01T00:00:00+00:00"
