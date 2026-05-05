"""
ML-based anomaly detection using scikit-learn IsolationForest.

Pipeline:
  1. train()    — fit IsolationForest on normal traffic features, save model
  2. predict()  — load model, score each time window
  3. generate_alerts() — convert anomaly flags to structured alerts

Dependencies: numpy, scikit-learn, joblib
"""

import json
import os
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
from pathlib import Path


def _load_ml_config():
    """Read ml.contamination from config.json."""
    cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        return cfg.get("ml", {}).get("contamination", 0.1)
    except Exception:
        return 0.1


class MLAnomalyDetector:
    """Unsupervised anomaly detection on network traffic feature vectors.

    Uses IsolationForest to identify time windows whose feature pattern
    deviates significantly from the learned "normal" baseline.

    Usage:
        detector = MLAnomalyDetector()
        detector.train(feature_matrix, "model.pkl")

        scores, is_anom = MLAnomalyDetector.predict(feature_matrix, "model.pkl")
        alerts = MLAnomalyDetector.generate_alerts(
            timestamps, is_anom, scores, feature_matrix, feature_names)
    """

    def __init__(self, contamination=None, random_state=42, n_estimators=200):
        """
        Args:
            contamination: Expected fraction of anomalies (default from config).
            random_state:  Reproducibility seed.
            n_estimators:  Number of isolation trees.
        """
        if contamination is None:
            contamination = _load_ml_config()
        self.contamination = contamination
        self.random_state = random_state
        self.n_estimators = n_estimators

    def train(self, feature_matrix, model_path="model.pkl"):
        """Train IsolationForest on normal-traffic feature matrix and save.

        Args:
            feature_matrix: np.ndarray [n_windows, n_features].
            model_path:     Where to persist the trained model.

        Returns:
            The fitted sklearn model.
        """
        if feature_matrix.shape[0] < 5:
            raise ValueError(f"Need >= 5 windows to train, got {feature_matrix.shape[0]}")

        model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
            n_estimators=self.n_estimators,
        )
        model.fit(feature_matrix)
        joblib.dump(model, model_path)
        print(f"[*] Model trained ({feature_matrix.shape[0]} samples, "
              f"{feature_matrix.shape[1]} features) -> {model_path}")
        return model

    @staticmethod
    def predict(feature_matrix, model_path="model.pkl"):
        """Load a saved model and predict on new features.

        Args:
            feature_matrix: np.ndarray [n_windows, n_features].
            model_path:     Path to joblib-saved IsolationForest.

        Returns:
            tuple[np.ndarray, np.ndarray]:
                anomaly_scores  — float array, lower = more anomalous
                is_anomaly      — bool array, True = anomaly
        """
        path = Path(model_path)
        if not path.exists():
            raise FileNotFoundError(
                f"Model not found: {model_path}.  Train first with .train().")

        model = joblib.load(model_path)
        scores = model.decision_function(feature_matrix)
        preds = model.predict(feature_matrix)
        is_anomaly = preds == -1

        return scores, is_anomaly

    @staticmethod
    def generate_alerts(timestamps, is_anomaly, anomaly_scores,
                        feature_matrix, feature_names):
        """Convert ML predictions into structured alert dicts.

        Severity by score:
          < -0.2   → high
          <  0.0   → medium
          else     → low

        Each alert also includes the top-3 features that deviate most
        from the overall mean, giving analysts a starting clue.

        Args:
            timestamps:      list[str] — one per window (ISO format).
            is_anomaly:      np.ndarray bool [n_windows].
            anomaly_scores:  np.ndarray float [n_windows].
            feature_matrix:  np.ndarray [n_windows, n_features].
            feature_names:   list[str] — feature labels.

        Returns:
            list[dict]  Alerts sorted by timestamp.
        """
        alerts = []
        global_mean = feature_matrix.mean(axis=0)
        global_std = feature_matrix.std(axis=0) + 1e-8  # avoid div-0

        for i in range(len(is_anomaly)):
            if not is_anomaly[i]:
                continue

            score = float(anomaly_scores[i])
            if score < -0.2:
                severity = "high"
            elif score < 0.0:
                severity = "medium"
            else:
                severity = "low"

            # top contributing features (largest z-score deviation)
            z = (feature_matrix[i] - global_mean) / global_std
            top_idx = np.argsort(np.abs(z))[::-1][:3]
            top_feats = [f"{feature_names[j]}={feature_matrix[i, j]:.2f} "
                         f"(z={z[j]:+.1f})" for j in top_idx]

            alerts.append({
                "timestamp": timestamps[i] if i < len(timestamps) else f"win_{i}",
                "type": "ML_Anomaly",
                "severity": severity,
                "anomaly_score": round(score, 4),
                "top_contributing_features": top_feats,
                "detail": (f"IsolationForest score={score:.4f}, "
                           f"top features: {', '.join(top_feats)}"),
            })

        alerts.sort(key=lambda a: a.get("timestamp", ""))
        return alerts


# ─── main ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    from feature_extractor import FeatureExtractor

    pcap = sys.argv[1] if len(sys.argv) > 1 else "quick_test.pcap"
    model_path = "model.pkl"

    fe = FeatureExtractor(window_size=10)
    X = fe.extract(pcap)
    names = fe.get_feature_names()
    detector = MLAnomalyDetector()

    if X.shape[0] < 5:
        print(f"[!] Only {X.shape[0]} windows -- need >= 5.  "
              f"Use a longer pcap or smaller window_size.")
        sys.exit(1)

    # train if model does not exist
    if not Path(model_path).exists():
        print(f"[*] Training model from {pcap} ...")
        detector.train(X, model_path)
    else:
        print(f"[*] Using existing model: {model_path}")

    # predict
    scores, is_anom = MLAnomalyDetector.predict(X, model_path)
    timestamps = [f"window_{i}" for i in range(len(scores))]

    print(f"  Windows:       {len(scores)}")
    print(f"  Anomalies:     {is_anom.sum()}")
    print(f"  Anomaly ratio: {is_anom.mean():.1%}\n")

    # alerts
    alerts = MLAnomalyDetector.generate_alerts(
        timestamps, is_anom, scores, X, names)
    if alerts:
        print(f"  {len(alerts)} ML alert(s):\n")
        for a in alerts:
            print(f"  [{a['severity'].upper():6s}] score={a['anomaly_score']}")
            print(f"         {a['detail']}\n")
    else:
        print("  No ML anomalies detected.")
