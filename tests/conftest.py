"""Shared pytest fixtures for ThreatSight tests."""

import os
import pytest


@pytest.fixture(scope="session")
def demo_pcap():
    """Return path to demo pcap file, skip tests if missing."""
    path = os.path.join(os.path.dirname(__file__), "..", "samples", "demo.pcap")
    path = os.path.abspath(path)
    if not os.path.exists(path):
        pytest.skip(f"Demo pcap not found: {path}")
    return path
