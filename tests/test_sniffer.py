"""Tests for sniffer.py static methods and helper functions."""

import os
import sys
import datetime
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sniffer import (
    _init_proto_stats, _count_protocols, _count_timeseries_proto,
    _PROTOCOL_RULES, _TIMESERIES_PROTOS, TrafficSniffer,
)


class TestHelperFunctions:
    """Test module-level helper functions."""

    def test_init_proto_stats_returns_all_protocols(self):
        stats = _init_proto_stats()
        expected = ['HTTP', 'DNS', 'TCP', 'UDP', 'ICMP', 'TLS/SSL', 'ARP']
        assert list(stats.keys()) == expected
        for v in stats.values():
            assert v == {'packets': 0, 'bytes': 0}

    def test_count_protocols_tcp(self):
        stats = _init_proto_stats()
        _count_protocols({'TCP'}, 100, stats)
        assert stats['TCP']['packets'] == 1
        assert stats['TCP']['bytes'] == 100
        assert stats['HTTP']['packets'] == 0

    def test_count_protocols_http_and_tcp(self):
        stats = _init_proto_stats()
        _count_protocols({'HTTP', 'TCP'}, 200, stats)
        assert stats['HTTP']['packets'] == 1
        assert stats['TCP']['packets'] == 1
        assert stats['HTTP']['bytes'] == 200

    def test_count_protocols_dns(self):
        stats = _init_proto_stats()
        _count_protocols({'DNS', 'UDP'}, 50, stats)
        assert stats['DNS']['packets'] == 1
        assert stats['UDP']['packets'] == 1

    def test_count_protocols_icmpv6(self):
        stats = _init_proto_stats()
        _count_protocols({'ICMPV6'}, 30, stats)
        assert stats['ICMP']['packets'] == 1

    def test_count_protocols_tls(self):
        stats = _init_proto_stats()
        _count_protocols({'TLS'}, 150, stats)
        assert stats['TLS/SSL']['packets'] == 1

    def test_count_protocols_arp(self):
        stats = _init_proto_stats()
        _count_protocols({'ARP'}, 28, stats)
        assert stats['ARP']['packets'] == 1
        assert stats['ARP']['bytes'] == 28

    def test_count_protocols_unknown(self):
        stats = _init_proto_stats()
        _count_protocols({'UNKNOWN'}, 10, stats)
        for v in stats.values():
            assert v['packets'] == 0

    def test_count_timeseries_proto(self):
        ts = {0: {'time': '0:00:05', 'HTTP': 0, 'DNS': 0, 'TCP': 0, 'UDP': 0, 'ICMP': 0}}
        _count_timeseries_proto({'HTTP', 'TCP'}, 0, ts)
        assert ts[0]['HTTP'] == 1
        assert ts[0]['TCP'] == 1
        assert ts[0]['DNS'] == 0

    def test_count_timeseries_proto_icmpv6(self):
        ts = {0: {'time': '0:00:05', 'HTTP': 0, 'DNS': 0, 'TCP': 0, 'UDP': 0, 'ICMP': 0}}
        _count_timeseries_proto({'ICMPV6'}, 0, ts)
        assert ts[0]['ICMP'] == 1


class TestProtocolRules:
    """Test protocol rule definitions."""

    def test_protocol_rules_count(self):
        assert len(_PROTOCOL_RULES) == 7

    def test_timeseries_protos(self):
        assert _TIMESERIES_PROTOS == ['HTTP', 'DNS', 'TCP', 'UDP', 'ICMP']


class TestGetSniffTime:
    """Test _get_sniff_time static method."""

    def test_valid_datetime(self):
        class FakePkt:
            sniff_time = datetime.datetime(2026, 1, 1, 12, 0, 0)
        ts = TrafficSniffer._get_sniff_time(FakePkt())
        assert ts == datetime.datetime(2026, 1, 1, 12, 0, 0)

    def test_invalid_sniff_time(self):
        class FakePkt:
            sniff_time = "not-a-date"
            sniff_timestamp = "2026-01-01T12:00:00.000000000Z"
        ts = TrafficSniffer._get_sniff_time(FakePkt())
        assert ts is not None

    def test_no_sniff_time(self):
        class FakePkt:
            sniff_time = None
            sniff_timestamp = ""
        ts = TrafficSniffer._get_sniff_time(FakePkt())
        assert ts is None


class TestAnalyzePcap:
    """Test TrafficSniffer.analyze_pcap static method."""

    def test_returns_dict_structure(self, demo_pcap):
        result = TrafficSniffer.analyze_pcap(demo_pcap, window_sec=5)
        assert 'stats' in result
        assert 'summary' in result
        assert 'time_series' in result

    def test_summary_fields(self, demo_pcap):
        result = TrafficSniffer.analyze_pcap(demo_pcap, window_sec=5)
        summary = result['summary']
        assert 'total_packets' in summary
        assert 'total_bytes' in summary
        assert 'duration_sec' in summary
        assert 'avg_packet_size' in summary

    def test_total_packets_positive(self, demo_pcap):
        result = TrafficSniffer.analyze_pcap(demo_pcap, window_sec=5)
        assert result['summary']['total_packets'] > 0

    def test_stats_not_empty(self, demo_pcap):
        result = TrafficSniffer.analyze_pcap(demo_pcap, window_sec=5)
        assert len(result['stats']) > 0

    def test_time_series_is_list(self, demo_pcap):
        result = TrafficSniffer.analyze_pcap(demo_pcap, window_sec=5)
        assert isinstance(result['time_series'], list)


class TestGetProtocolStats:
    """Test TrafficSniffer.get_protocol_stats static method."""

    def test_returns_all_protocols(self, demo_pcap):
        stats = TrafficSniffer.get_protocol_stats(demo_pcap)
        expected = ['HTTP', 'DNS', 'TCP', 'UDP', 'ICMP', 'TLS/SSL', 'ARP']
        assert list(stats.keys()) == expected

    def test_tcp_has_packets(self, demo_pcap):
        stats = TrafficSniffer.get_protocol_stats(demo_pcap)
        assert stats['TCP']['packets'] > 0

    def test_bytes_positive(self, demo_pcap):
        stats = TrafficSniffer.get_protocol_stats(demo_pcap)
        for proto, data in stats.items():
            if data['packets'] > 0:
                assert data['bytes'] > 0


class TestGetFlowSummary:
    """Test TrafficSniffer.get_flow_summary static method."""

    def test_returns_summary(self, demo_pcap):
        summary = TrafficSniffer.get_flow_summary(demo_pcap)
        assert summary['total_packets'] > 0
        assert summary['total_bytes'] > 0
        assert summary['duration_sec'] >= 0
        assert summary['avg_packet_size'] > 0


class TestGetProtocolTimeseries:
    """Test TrafficSniffer.get_protocol_timeseries static method."""

    def test_returns_list(self, demo_pcap):
        ts = TrafficSniffer.get_protocol_timeseries(demo_pcap, window_sec=5)
        assert isinstance(ts, list)
        assert len(ts) > 0

    def test_entries_have_time(self, demo_pcap):
        ts = TrafficSniffer.get_protocol_timeseries(demo_pcap, window_sec=5)
        for entry in ts:
            assert 'time' in entry

    def test_entries_have_protocol_keys(self, demo_pcap):
        ts = TrafficSniffer.get_protocol_timeseries(demo_pcap, window_sec=5)
        for entry in ts:
            assert 'HTTP' in entry
            assert 'DNS' in entry
            assert 'TCP' in entry

    def test_different_window_sizes(self, demo_pcap):
        ts5 = TrafficSniffer.get_protocol_timeseries(demo_pcap, window_sec=5)
        ts10 = TrafficSniffer.get_protocol_timeseries(demo_pcap, window_sec=10)
        # Smaller window should produce more or equal buckets
        assert len(ts5) >= len(ts10)


class TestInitProtoStats:
    """Test _init_proto_stats helper."""

    def test_returns_dict(self):
        stats = _init_proto_stats()
        assert isinstance(stats, dict)

    def test_all_values_zero(self):
        stats = _init_proto_stats()
        for v in stats.values():
            assert v['packets'] == 0
            assert v['bytes'] == 0


class TestCountProtocolsEdgeCases:
    """Edge cases for _count_protocols."""

    def test_empty_proto_names(self):
        stats = _init_proto_stats()
        _count_protocols(set(), 100, stats)
        for v in stats.values():
            assert v['packets'] == 0

    def test_multiple_protocols_increment(self):
        stats = _init_proto_stats()
        _count_protocols({'HTTP', 'TCP'}, 100, stats)
        _count_protocols({'HTTP', 'TCP'}, 200, stats)
        assert stats['HTTP']['packets'] == 2
        assert stats['HTTP']['bytes'] == 300
        assert stats['TCP']['packets'] == 2

    def test_zero_bytes(self):
        stats = _init_proto_stats()
        _count_protocols({'TCP'}, 0, stats)
        assert stats['TCP']['packets'] == 1
        assert stats['TCP']['bytes'] == 0


class TestCountTimeseriesProtoEdgeCases:
    """Edge cases for _count_timeseries_proto."""

    def test_multiple_buckets(self):
        ts = {
            0: {'time': '0:00:05', 'HTTP': 0, 'DNS': 0, 'TCP': 0, 'UDP': 0, 'ICMP': 0},
            5: {'time': '0:00:10', 'HTTP': 0, 'DNS': 0, 'TCP': 0, 'UDP': 0, 'ICMP': 0},
        }
        _count_timeseries_proto({'HTTP'}, 0, ts)
        _count_timeseries_proto({'HTTP'}, 5, ts)
        assert ts[0]['HTTP'] == 1
        assert ts[5]['HTTP'] == 1

    def test_unknown_protocol_ignored(self):
        ts = {0: {'time': '0:00:05', 'HTTP': 0, 'DNS': 0, 'TCP': 0, 'UDP': 0, 'ICMP': 0}}
        _count_timeseries_proto({'UNKNOWN'}, 0, ts)
        for v in ts[0].values():
            if isinstance(v, int):
                assert v == 0
