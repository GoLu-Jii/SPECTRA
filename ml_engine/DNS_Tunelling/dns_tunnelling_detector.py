"""Inference wrapper for the DNS tunnelling XGBoost model."""

from __future__ import annotations

from pathlib import Path
from typing import Mapping

import joblib
import pandas as pd


FEATURE_ORDER = [
    "Duration",
    "FlowBytesSent",
    "FlowSentRate",
    "FlowBytesReceived",
    "FlowReceivedRate",
    "PacketLengthVariance",
    "PacketLengthStandardDeviation",
    "PacketLengthMean",
    "PacketLengthMedian",
    "PacketLengthMode",
    "PacketLengthSkewFromMedian",
    "PacketLengthSkewFromMode",
    "PacketLengthCoefficientofVariation",
    "PacketTimeVariance",
    "PacketTimeStandardDeviation",
    "PacketTimeMean",
    "PacketTimeMedian",
    "PacketTimeMode",
    "PacketTimeSkewFromMedian",
    "PacketTimeSkewFromMode",
    "PacketTimeCoefficientofVariation",
    "ResponseTimeTimeVariance",
    "ResponseTimeTimeStandardDeviation",
    "ResponseTimeTimeMean",
    "ResponseTimeTimeMedian",
    "ResponseTimeTimeMode",
    "ResponseTimeTimeSkewFromMedian",
    "ResponseTimeTimeSkewFromMode",
    "ResponseTimeTimeCoefficientofVariation",
]
THRESHOLD = 0.50


class DNSTunnellingDetector:
    def __init__(self, model_path: str | Path | None = None, threshold: float = THRESHOLD) -> None:
        artifact_path = Path(model_path) if model_path else Path(__file__).with_name("dns_tunnelling_xgb_model.pkl")
        self.model = joblib.load(artifact_path)
        self.threshold = threshold

    def transform(self, flow_features: Mapping[str, object]) -> pd.DataFrame:
        missing = [name for name in FEATURE_ORDER if name not in flow_features]
        if missing:
            raise ValueError(f"Missing DNS tunnelling features: {', '.join(missing)}")
        frame = pd.DataFrame([[flow_features[name] for name in FEATURE_ORDER]], columns=FEATURE_ORDER)
        return frame.apply(pd.to_numeric, errors="raise").fillna(0)

    def predict(self, flow_features: Mapping[str, object]) -> tuple[int, float, dict[str, object]]:
        features = self.transform(flow_features)
        confidence = float(self.model.predict_proba(features)[0][1])
        alert = int(confidence >= self.threshold)
        evidence = {name: features.iloc[0][name] for name in FEATURE_ORDER}
        evidence["prediction"] = "Malicious DNS tunnel (1)" if alert else "Benign DoH (0)"
        return alert, confidence, evidence