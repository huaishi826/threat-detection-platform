"""Tests for rule_detector.py — rule-based threat detection."""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import rule_detector


class TestDetectSynFlood:
    """SYN Flood detection tests."""

    def test_detects_syn_flood_in_demo_pcap(self, demo_pcap):
        """Demo pcap should contain at least one SYN_Flood alert."""
        alerts = rule_detector.detect_syn_flood(demo_pcap)
        syn_alerts = [a for a in alerts if a["type"] == "SYN_Flood"]
        assert len(syn_alerts) >= 1, "Expected at least one SYN_Flood alert"
        assert syn_alerts[0]["severity"] == "high"

    def test_syn_flood_alert_fields(self, demo_pcap):
        """Alert dict should contain required fields."""
        alerts = rule_detector.detect_syn_flood(demo_pcap)
        if alerts:
            required = {"timestamp", "type", "severity", "source_ip", "detail"}
            assert required.issubset(set(alerts[0].keys()))

    def test_returns_list(self, demo_pcap):
        """Always returns a list, never None."""
        result = rule_detector.detect_syn_flood(demo_pcap)
        assert isinstance(result, list)


class TestDetectDnsTunnel:
    """DNS Tunnel detection tests."""

    def test_detects_dns_tunnel_in_demo_pcap(self, demo_pcap):
        """Demo pcap should contain DNS_Tunnel alerts."""
        alerts = rule_detector.detect_dns_tunnel(demo_pcap)
        dns_alerts = [a for a in alerts if a["type"] == "DNS_Tunnel"]
        assert len(dns_alerts) >= 1, "Expected at least one DNS_Tunnel alert"
        assert dns_alerts[0]["severity"] == "medium"

    def test_dns_tunnel_alert_has_detail(self, demo_pcap):
        """DNS tunnel alerts should have domain info in detail."""
        alerts = rule_detector.detect_dns_tunnel(demo_pcap)
        if alerts:
            assert "queries" in alerts[0]["detail"].lower() or \
                   "length" in alerts[0]["detail"].lower()


class TestDetectPortScan:
    """Port Scan detection tests."""

    def test_returns_list(self, demo_pcap):
        """Always returns a list."""
        result = rule_detector.detect_port_scan(demo_pcap)
        assert isinstance(result, list)


class TestDetectAll:
    """Combined detection tests."""

    def test_detect_all_returns_merged_alerts(self, demo_pcap):
        """detect_all should return alerts sorted by timestamp."""
        alerts = rule_detector.detect_all(demo_pcap)
        assert isinstance(alerts, list)
        if len(alerts) > 1:
            # verify sorted by timestamp
            for i in range(len(alerts) - 1):
                assert alerts[i].get("timestamp", "") <= alerts[i + 1].get("timestamp", "")

    def test_detect_all_has_multiple_types(self, demo_pcap):
        """Demo pcap should trigger at least 2 different alert types."""
        alerts = rule_detector.detect_all(demo_pcap)
        types = {a["type"] for a in alerts}
        assert len(types) >= 2, f"Expected >=2 alert types, got {types}"


class TestConfigLoader:
    """Config loading tests."""

    def test_load_rules_config_returns_dict(self):
        """Config loader should return a dict with expected keys."""
        cfg = rule_detector.load_rules_config()
        assert isinstance(cfg, dict)
        assert "syn_flood" in cfg
        assert "dns_tunnel" in cfg
        assert "port_scan" in cfg

    def test_syn_flood_config_has_threshold(self):
        """SYN flood config should contain threshold key."""
        cfg = rule_detector.load_rules_config()
        assert "threshold" in cfg["syn_flood"]
        assert 0 < cfg["syn_flood"]["threshold"] <= 1
