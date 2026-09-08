"""Inference wrapper for the 23-feature C2 Random Forest artifact."""

from __future__ import annotations

from pathlib import Path
from typing import Mapping

import joblib
import numpy as np
import pandas as pd


FEATURE_ORDER = [
    "Dur", "Pkts", "Bytes", "IAT", "IAT_Variance", "IAT_Std",
    "Bytes_Variance", "Bytes_Per_Packet", "Proto_esp", "Proto_icmp",
    "Proto_igmp", "Proto_ipv6", "Proto_ipv6-icmp", "Proto_ipx/spx",
    "Proto_pim", "Proto_rarp", "Proto_rtcp", "Proto_rtp", "Proto_tcp",
    "Proto_udp", "Proto_udt", "Proto_unas", "FlowDir_Reverse",
]
PROTOCOL_FEATURES = FEATURE_ORDER[8:22]


class C2BeaconingDetector:
    """Score C2 flow windows with the saved 23-feature Random Forest model."""

    def __init__(self, model_path: str | Path | None = None, threshold: float = 0.20) -> None:
        artifact_path = Path(model_path) if model_path else Path(__file__).with_name("botnet_c2_detector.pkl")
        self.model = joblib.load(artifact_path)
        self.threshold = threshold
        model_features = list(getattr(self.model, "feature_names_in_", []))
        if getattr(self.model, "n_features_in_", None) != len(FEATURE_ORDER):
            raise ValueError(f"C2 model expects {getattr(self.model, 'n_features_in_', 'unknown')} features")
        if model_features and model_features != FEATURE_ORDER:
            raise ValueError(f"C2 model feature order does not match: {model_features}")

    def predict_features(self, features: Mapping[str, object]) -> tuple[int, float, dict[str, object]]:
        """Predict from one already-engineered 23-feature record."""
        missing = [name for name in FEATURE_ORDER if name not in features]
        if missing:
            raise ValueError(f"Missing C2 features: {', '.join(missing)}")
        row = pd.DataFrame([[features[name] for name in FEATURE_ORDER]], columns=FEATURE_ORDER)
        row = row.apply(pd.to_numeric, errors="raise")
        confidence = float(self.model.predict_proba(row)[0][1])
        alert = int(confidence >= self.threshold)
        evidence = {name: row.iloc[0][name].item() for name in FEATURE_ORDER}
        evidence.update({"prediction": "Botnet C2 (1)" if alert else "Normal (0)", "threshold": self.threshold})
        return alert, confidence, evidence

    def extract_features(self, flows: list[dict]) -> dict[str, float]:
        """Aggregate flows into the model's 23 features.

        Each flow needs ``start_time_unix``; ``bytes`` and ``pkts`` default to
        zero. Protocol is read from ``proto`` or ``protocol``.
        """
        if len(flows) < 2:
            raise ValueError("At least two flows are required to calculate IAT features")
        ordered = sorted(flows, key=lambda flow: float(flow["start_time_unix"]))
        timestamps = np.asarray([float(flow["start_time_unix"]) for flow in ordered])
        packets = np.asarray([float(flow.get("pkts", 0)) for flow in ordered])
        byte_values = np.asarray([float(flow.get("bytes", 0)) for flow in ordered])
        iats = np.diff(timestamps)
        protocols = {str(flow.get("proto", flow.get("protocol", ""))).lower() for flow in ordered}
        total_packets = float(np.sum(packets))
        features = {
            "Dur": float(timestamps[-1] - timestamps[0]),
            "Pkts": total_packets,
            "Bytes": float(np.sum(byte_values)),
            "IAT": float(np.mean(iats)),
            "IAT_Variance": float(np.var(iats)),
            "IAT_Std": float(np.std(iats)),
            "Bytes_Variance": float(np.var(byte_values)),
            "Bytes_Per_Packet": float(np.sum(byte_values) / total_packets) if total_packets else 0.0,
            "FlowDir_Reverse": float(any(bool(flow.get("flow_dir_reverse", False)) for flow in ordered)),
        }
        for feature in PROTOCOL_FEATURES:
            features[feature] = float(feature.removeprefix("Proto_").lower() in protocols)
        return {name: features[name] for name in FEATURE_ORDER}

    def predict(self, flows: list[dict]) -> tuple[int, float, dict[str, object]]:
        return self.predict_features(self.extract_features(flows))