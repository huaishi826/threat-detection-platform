"""Tests for feature_extractor.py — 14-dim feature matrix extraction."""

import sys
import os
import pytest
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import feature_extractor


class TestFeatureExtractor:
    """Feature extraction tests."""

    def setup_method(self):
        self.fe = feature_extractor.FeatureExtractor(window_size=10)

    def test_extract_shape_columns(self, demo_pcap):
        """Feature matrix should have 14 columns (features)."""
        X = self.fe.extract(demo_pcap)
        assert X.ndim == 2, f"Expected 2D array, got {X.ndim}D"
        assert X.shape[1] == 14, f"Expected 14 features, got {X.shape[1]}"

    def test_extract_not_empty(self, demo_pcap):
        """Demo pcap should produce at least one feature row."""
        X = self.fe.extract(demo_pcap)
        assert X.shape[0] > 0, "Feature matrix is empty"

    def test_feature_names_count(self):
        """get_feature_names() should return 14 names."""
        names = self.fe.get_feature_names()
        assert len(names) == 14

    def test_feature_names_content(self):
        """Feature names should include key metrics."""
        names = self.fe.get_feature_names()
        assert "packets_per_sec" in names
        assert "syn_ratio" in names
        assert "dns_ratio" in names

    def test_ratios_in_range(self, demo_pcap):
        """All ratio features should be in [0, 1]."""
        X = self.fe.extract(demo_pcap)
        for col_idx in [2, 3, 4, 5, 8, 9, 10, 11, 12, 13]:  # ratio columns
            col = X[:, col_idx]
            assert np.all(col >= 0) and np.all(col <= 1), \
                f"Column {col_idx} has values outside [0, 1]"

    def test_no_nan_values(self, demo_pcap):
        """Feature matrix should not contain NaN."""
        X = self.fe.extract(demo_pcap)
        assert not np.isnan(X).any(), "Feature matrix contains NaN values"

    def test_custom_window_size(self, demo_pcap):
        """Different window sizes should affect row count."""
        fe_5 = feature_extractor.FeatureExtractor(window_size=5)
        fe_20 = feature_extractor.FeatureExtractor(window_size=20)
        X5 = fe_5.extract(demo_pcap)
        X20 = fe_20.extract(demo_pcap)
        # smaller window = more rows
        assert X5.shape[0] >= X20.shape[0], \
            "Smaller window should produce >= rows"
