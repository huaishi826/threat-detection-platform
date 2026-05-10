"""Shared pytest fixtures for ThreatSight tests."""

import os
import sys
import pytest

# Ensure project root is on sys.path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture(scope="session")
def demo_pcap():
    """Return path to demo pcap file, skip tests if missing."""
    path = os.path.join(os.path.dirname(__file__), "..", "samples", "demo.pcap")
    path = os.path.abspath(path)
    if not os.path.exists(path):
        pytest.skip(f"Demo pcap not found: {path}")
    return path


@pytest.fixture(scope="session")
def app():
    """Create Flask app in test mode."""
    os.environ["DEMO_MODE"] = "false"
    from app import app as flask_app, db
    flask_app.config["TESTING"] = True
    flask_app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    with flask_app.app_context():
        db.create_all()
    yield flask_app
    with flask_app.app_context():
        db.drop_all()


@pytest.fixture(scope="session")
def client(app):
    """Flask test client."""
    return app.test_client()


@pytest.fixture(autouse=True)
def _setup_app_context(app):
    """Push app context for every test."""
    with app.app_context():
        yield
