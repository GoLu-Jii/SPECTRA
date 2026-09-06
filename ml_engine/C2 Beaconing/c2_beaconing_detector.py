import joblib
import numpy as np
from scipy.stats import entropy
from collections import Counter

FEATURE_ORDER = [
    "iat_mean",
    "iat_std",
    "iat_cv",
    "flow_count",
    "bytes_mean",
    "bytes_std",
    "pkts_mean",
    "dest_port_entropy"
]

class C2BeaconingDetector:
    """
    Inference engine for Botnet C2 Beaconing detection.
    Consumes chronological sliding-window flow sequences for a specific (SrcIP, DstIP) pair.
    """
    def __init__(self, model_path="models/c2_beaconing_rf.pkl", threshold=0.85):
        self.model = joblib.load(model_path)
        self.threshold = threshold

    def extract_features(self, flows: list[dict]):
        """
        Calculates the 8 behavioral features from an active buffer of flows.
        Expects a list of dictionaries with keys:
            'start_time_unix', 'bytes', 'pkts', 'dst_port'
        """
        if len(flows) < 4:
            return None, None

        # Sort strictly chronologically
        flows_sorted = sorted(flows, key=lambda x: x["start_time_unix"])
        timestamps = np.array([float(f["start_time_unix"]) for f in flows_sorted], dtype=np.float64)
        bytes_arr = np.array([float(f.get("bytes", 0)) for f in flows_sorted], dtype=np.float64)
        pkts_arr = np.array([float(f.get("pkts", 1)) for f in flows_sorted], dtype=np.float64)
        ports = [f.get("dst_port", 0) for f in flows_sorted]

        # Inter-Arrival Time metrics
        iats = np.diff(timestamps)
        iat_mean = float(np.mean(iats))
        iat_std = float(np.std(iats))
        iat_cv = float(iat_std / (iat_mean + 1e-6))

        # Port entropy
        port_counts = list(Counter(ports).values())
        port_ent = float(entropy(port_counts)) if len(port_counts) > 0 else 0.0

        raw_metrics = {
            "iat_mean": iat_mean,
            "iat_std": iat_std,
            "iat_cv": iat_cv,
            "flow_count": len(flows_sorted),
            "bytes_mean": float(np.mean(bytes_arr)),
            "bytes_std": float(np.std(bytes_arr)),
            "pkts_mean": float(np.mean(pkts_arr)),
            "dest_port_entropy": port_ent,
            "window_duration": float(timestamps[-1] - timestamps[0])
        }

        # Build feature vector matching exact contract
        feature_vector = np.array([[raw_metrics[col] for col in FEATURE_ORDER]], dtype=np.float32)
        return feature_vector, raw_metrics

    def predict(self, flows: list[dict]):
        """
        Evaluates active flow window for periodic C2 beaconing patterns.

        Returns:
            is_alert (int): 1 if confidence >= threshold, else 0.
            confidence (float): Posterior probability of malicious class (0.0 to 1.0).
            evidence (dict): Supporting statistical payload for standardized alerts.
        """
        feature_vector, raw_metrics = self.extract_features(flows)
        if feature_vector is None:
            return 0, 0.0, {}

        # Inference using Random Forest probability distribution
        confidence = float(self.model.predict_proba(feature_vector)[0][1])
        is_alert = int(confidence >= self.threshold)

        evidence = {
            "mean_iat_seconds": round(raw_metrics["iat_mean"], 2),
            "iat_variance": round(raw_metrics["iat_std"] ** 2, 4),
            "coefficient_of_variation": round(raw_metrics["iat_cv"], 4),
            "flows_in_window": raw_metrics["flow_count"],
            "window_duration_seconds": round(raw_metrics["window_duration"], 2),
            "summary": (
                f"Observed {raw_metrics['flow_count']} periodic connections across "
                f"{round(raw_metrics['window_duration'], 1)}s window with timing jitter "
                f"(CV: {raw_metrics['iat_cv']:.4f}, IAT StdDev: {raw_metrics['iat_std']:.2f}s)."
            )
        }

        return is_alert, confidence, evidence

if __name__ == "__main__":
    # Internal Verification Test
    print("[*] Running synthetic validation sanity check...")
    
    # Simulating a persistent 60s C2 beacon
    synthetic_c2_flows = [
        {"start_time_unix": 1700000000.0, "bytes": 120, "pkts": 2, "dst_port": 80},
        {"start_time_unix": 1700000060.1, "bytes": 124, "pkts": 2, "dst_port": 80},
        {"start_time_unix": 1700000120.2, "bytes": 118, "pkts": 2, "dst_port": 80},
        {"start_time_unix": 1700000180.1, "bytes": 122, "pkts": 2, "dst_port": 80},
        {"start_time_unix": 1700000240.3, "bytes": 120, "pkts": 2, "dst_port": 80}
    ]

    try:
        detector = C2BeaconingDetector(model_path="models/c2_beaconing_rf.pkl", threshold=0.80)
        alert, conf, ev = detector.predict(synthetic_c2_flows)
        print(f"Alert: {alert} | Confidence: {conf:.4f}")
        print(f"Evidence: {ev}")
    except FileNotFoundError:
        print("[!] Note: 'models/c2_beaconing_rf.pkl' not found on local disk. Run 'train_c2_model.py' first.")