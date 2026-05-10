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


class TestMlDetectorEdgeCases:
    """Edge case tests for ML detector."""

    def test_train_too_few_samples(self, tmp_path):
        """train() should raise ValueError with fewer than 5 samples."""
        X = np.array([[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]])
        model_path = str(tmp_path / "model.pkl")
        detector = ml_detector.MLAnomalyDetector(contamination=0.1)
        with pytest.raises(ValueError, match="Need >= 5"):
            detector.train(X, model_path)

    def test_predict_nonexistent_model(self):
        """predict() should raise FileNotFoundError for missing model."""
        X = np.random.rand(10, 14)
        with pytest.raises(FileNotFoundError):
            ml_detector.MLAnomalyDetector.predict(X, "/nonexistent/model.pkl")

    def test_generate_alerts_severity_high(self):
        """Scores < -0.2 should produce 'high' severity."""
        n = 10
        X = np.random.rand(n, 14)
        scores = np.array([-0.5, -0.3, -0.1, 0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6])
        is_anom = np.array([True, True, True, True, True, False, False, False, False, False])
        timestamps = [f"t{i}" for i in range(n)]
        names = [f"f{i}" for i in range(14)]
        alerts = ml_detector.MLAnomalyDetector.generate_alerts(
            timestamps, is_anom, scores, X, names)
        severities = {a["severity"] for a in alerts}
        assert "high" in severities

    def test_generate_alerts_severity_medium(self):
        """Scores in [-0.2, 0.0) should produce 'medium' severity."""
        X = np.random.rand(5, 14)
        scores = np.array([-0.15, -0.05, -0.01, 0.0, 0.1])
        is_anom = np.array([True, True, True, True, True])
        timestamps = [f"t{i}" for i in range(5)]
        names = [f"f{i}" for i in range(14)]
        alerts = ml_detector.MLAnomalyDetector.generate_alerts(
            timestamps, is_anom, scores, X, names)
        for a in alerts:
            assert a["severity"] in ("high", "medium", "low")

    def test_generate_alerts_no_anomalies(self):
        """No anomalies should produce empty alerts."""
        X = np.random.rand(5, 14)
        scores = np.array([0.1, 0.2, 0.3, 0.4, 0.5])
        is_anom = np.array([False, False, False, False, False])
        timestamps = [f"t{i}" for i in range(5)]
        names = [f"f{i}" for i in range(14)]
        alerts = ml_detector.MLAnomalyDetector.generate_alerts(
            timestamps, is_anom, scores, X, names)
        assert alerts == []

    def test_generate_alerts_top_features(self):
        """Alerts should include top contributing features."""
        X = np.random.rand(5, 14)
        X[0, 0] = 100.0  # Make first feature anomalous
        scores = np.array([-0.5, 0.1, 0.2, 0.3, 0.4])
        is_anom = np.array([True, False, False, False, False])
        timestamps = [f"t{i}" for i in range(5)]
        names = [f"f{i}" for i in range(14)]
        alerts = ml_detector.MLAnomalyDetector.generate_alerts(
            timestamps, is_anom, scores, X, names)
        assert len(alerts) == 1
        assert "top_contributing_features" in alerts[0]
        assert len(alerts[0]["top_contributing_features"]) <= 3

    def test_random_state_reproducibility(self, demo_pcap, tmp_path):
        """Same random_state should produce same model."""
        fe = feature_extractor.FeatureExtractor(window_size=1)
        X = fe.extract(demo_pcap)
        if X.shape[0] < 5:
            pytest.skip("Not enough windows")

        model_path1 = str(tmp_path / "m1.pkl")
        model_path2 = str(tmp_path / "m2.pkl")
        d1 = ml_detector.MLAnomalyDetector(contamination=0.1, random_state=42)
        d2 = ml_detector.MLAnomalyDetector(contamination=0.1, random_state=42)
        d1.train(X, model_path1)
        d2.train(X, model_path2)

        s1, a1 = ml_detector.MLAnomalyDetector.predict(X, model_path1)
        s2, a2 = ml_detector.MLAnomalyDetector.predict(X, model_path2)
        np.testing.assert_array_equal(a1, a2)
