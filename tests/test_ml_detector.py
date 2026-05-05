"""Tests for ml_detector.py — Isolation Forest anomaly detection."""

import sys
import os
import pytest
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import ml_detector
import feature_extractor


class TestMlDetector:
    """ML anomaly detection tests."""

    def test_train_and_predict(self, demo_pcap, tmp_path):
        """Full pipeline: extract features → train → predict."""
        fe = feature_extractor.FeatureExtractor(window_size=1)
        X = fe.extract(demo_pcap)
        if X.shape[0] < 5:
            pytest.skip(f"Only {X.shape[0]} windows, need >=5 for ML training")

        model_path = str(tmp_path / "test_model.pkl")
        detector = ml_detector.MLAnomalyDetector(contamination=0.1)
        model = detector.train(X, model_path)
        assert model is not None

        scores, is_anom = ml_detector.MLAnomalyDetector.predict(X, model_path)
        assert len(scores) == X.shape[0]
        assert len(is_anom) == X.shape[0]

    def test_generate_alerts(self, demo_pcap, tmp_path):
        """generate_alerts should return list of dicts with required fields."""
        fe = feature_extractor.FeatureExtractor(window_size=1)
        X = fe.extract(demo_pcap)
        if X.shape[0] < 5:
            pytest.skip(f"Only {X.shape[0]} windows, need >=5 for ML training")

        model_path = str(tmp_path / "test_model.pkl")
        detector = ml_detector.MLAnomalyDetector(contamination=0.1)
        detector.train(X, model_path)

        scores, is_anom = ml_detector.MLAnomalyDetector.predict(X, model_path)
        timestamps = [f"window_{i}" for i in range(len(scores))]
        alerts = ml_detector.MLAnomalyDetector.generate_alerts(
            timestamps, is_anom, scores, X, fe.get_feature_names())
        assert isinstance(alerts, list)
        for alert in alerts:
            assert "type" in alert
            assert "severity" in alert
            assert alert["type"] == "ML_Anomaly"

    def test_contamination_from_config(self):
        """ML detector should read contamination from config.json."""
        import json
        cfg_path = os.path.join(os.path.dirname(__file__), "..", "config.json")
        if os.path.exists(cfg_path):
            with open(cfg_path) as f:
                cfg = json.load(f)
            expected = cfg.get("ml", {}).get("contamination", 0.1)
            detector = ml_detector.MLAnomalyDetector()
            assert detector.contamination == expected, \
                f"Expected contamination {expected}, got {detector.contamination}"
