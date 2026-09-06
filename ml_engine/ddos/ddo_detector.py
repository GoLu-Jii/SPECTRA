"""
DDoS Threat Detector implementation adhering to BaseThreatDetector interface.
Derived from XGBoost model and feature pipeline in train_ddos.ipynb.
"""

from __future__ import annotations

import math
from collections import defaultdict, deque
from datetime import timedelta
from pathlib import Path
from typing import Dict, Any, Optional, List

import numpy as np
import pandas as pd
import joblib

from ml_engine.interface import (
    BaseThreatDetector,
    DetectorMetadata,
    ThreatClass,
    Prediction,
)

# 26 features expected by the trained XGBoost model
FEATURE_NAMES = [
    "packets_per_second",
    "bytes_per_second",
    "byte_asymmetry",
    "packet_asymmetry",
    "bidirectional_ratio",
    "syn_ratio",
    "rst_ratio",
    "syn_without_data",
    "unique_source_ips_5s",
    "source_ip_entropy_5s",
    "flows_30s",
    "unique_sources_30s",
    "protocol_diversity_30s",
    "byte_rate_mean_30s",
    "flows_60s",
    "unique_sources_60s",
    "protocol_diversity_60s",
    "byte_rate_mean_60s",
    "protocolName_igmp",
    "protocolName_ip",
    "protocolName_ipv6icmp",
    "protocolName_tcp_ip",
    "protocolName_udp_ip",
    "direction_L2R",
    "direction_R2L",
    "direction_R2R",
]

CONTINUOUS_COLS = [
    "packets_per_second",
    "bytes_per_second",
    "unique_source_ips_5s",
    "source_ip_entropy_5s",
    "byte_asymmetry",
    "packet_asymmetry",
    "bidirectional_ratio",
    "flows_30s",
    "unique_sources_30s",
    "protocol_diversity_30s",
    "byte_rate_mean_30s",
    "flows_60s",
    "unique_sources_60s",
    "protocol_diversity_60s",
    "byte_rate_mean_60s",
]

DEFAULT_MODEL_FILENAME = "xgboost_ddos_model.pkl"
DEFAULT_SCALER_FILENAME = "robust_scaler.pkl"
PRODUCTION_THRESHOLD = 0.1


def _entropy(values: List[Any]) -> float:
    """Calculate Shannon entropy for discrete values."""
    if not values:
        return 0.0
    counts: Dict[Any, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    total = len(values)
    return -sum(
        (count / total) * math.log2(count / total)
        for count in counts.values()
    )


class DDoSFeatureWindow:
    """
    Stateful feature aggregator that builds 5s, 30s, and 60s behavioral metrics
    from streaming raw flow events per destination server.
    """

    def __init__(self) -> None:
        self.events: Dict[str, deque] = defaultdict(deque)

    def build_features(self, event: dict) -> dict:
        event = dict(event)

        start = pd.to_datetime(event["startDateTime"])
        stop = pd.to_datetime(event["stopDateTime"])

        src = event.get("source") or event.get("src_ip") or "0.0.0.0"
        dst = event.get("destination") or event.get("dst_ip") or "0.0.0.0"
        protocol = str(event.get("protocolName") or event.get("protocol") or "tcp_ip")
        direction = str(event.get("direction") or "L2R")

        src_bytes = float(event.get("totalSourceBytes", event.get("orig_bytes", 0)))
        dst_bytes = float(event.get("totalDestinationBytes", event.get("resp_bytes", 0)))
        src_packets = float(event.get("totalSourcePackets", event.get("orig_pkts", 0)))
        dst_packets = float(event.get("totalDestinationPackets", event.get("resp_pkts", 0)))

        duration = max((stop - start).total_seconds(), 0.001)
        total_bytes = src_bytes + dst_bytes
        total_packets = src_packets + dst_packets

        flags = str(event.get("sourceTCPFlagsDescription") or event.get("history") or "")
        syn_ratio = int("S" in flags or "s" in flags)
        rst_ratio = int("R" in flags or "r" in flags)

        base = {
            "timestamp": start,
            "source": src,
            "destination": dst,
            "protocolName": protocol,
            "direction": direction,
            "bytes_per_second": total_bytes / duration,
            "packets_per_second": total_packets / duration,
            "byte_asymmetry": abs(src_bytes - dst_bytes) / (total_bytes + 1),
            "packet_asymmetry": abs(src_packets - dst_packets) / (total_packets + 1),
            "bidirectional_ratio": dst_bytes / (total_bytes + 1),
            "syn_ratio": syn_ratio,
            "rst_ratio": rst_ratio,
            "syn_without_data": int(syn_ratio == 1 and src_bytes < 100),
        }

        q = self.events[dst]
        cutoff = start - timedelta(seconds=60)
        while q and q[0]["timestamp"] < cutoff:
            q.popleft()

        q.append(base)

        events_5 = [e for e in q if e["timestamp"] >= start - timedelta(seconds=5)]
        events_30 = [e for e in q if e["timestamp"] >= start - timedelta(seconds=30)]
        events_60 = list(q)

        features = {
            "packets_per_second": base["packets_per_second"],
            "bytes_per_second": base["bytes_per_second"],
            "byte_asymmetry": base["byte_asymmetry"],
            "packet_asymmetry": base["packet_asymmetry"],
            "bidirectional_ratio": base["bidirectional_ratio"],
            "syn_ratio": base["syn_ratio"],
            "rst_ratio": base["rst_ratio"],
            "syn_without_data": base["syn_without_data"],

            "unique_source_ips_5s": len({e["source"] for e in events_5}),
            "source_ip_entropy_5s": _entropy([e["source"] for e in events_5]),

            "flows_30s": len(events_30),
            "unique_sources_30s": len({e["source"] for e in events_30}),
            "protocol_diversity_30s": len({e["protocolName"] for e in events_30}),
            "byte_rate_mean_30s": (
                sum(e["bytes_per_second"] for e in events_30) / len(events_30)
                if events_30 else 0.0
            ),

            "flows_60s": len(events_60),
            "unique_sources_60s": len({e["source"] for e in events_60}),
            "protocol_diversity_60s": len({e["protocolName"] for e in events_60}),
            "byte_rate_mean_60s": (
                sum(e["bytes_per_second"] for e in events_60) / len(events_60)
                if events_60 else 0.0
            ),
        }

        for p in ["igmp", "ip", "ipv6icmp", "tcp_ip", "udp_ip"]:
            features[f"protocolName_{p}"] = int(protocol == p)

        for d in ["L2R", "R2L", "R2R"]:
            features[f"direction_{d}"] = int(direction == d)

        return features


class DDoSDetector(BaseThreatDetector):
    """
    DDoS Threat Detector implementing BaseThreatDetector contract.
    Loads trained XGBoost model and RobustScaler for inference.
    """

    def __init__(
        self,
        model_path: Optional[str] = None,
        scaler_path: Optional[str] = None,
        threshold: float = PRODUCTION_THRESHOLD,
    ) -> None:
        self.threshold = float(threshold)
        self.window = DDoSFeatureWindow()
        self.model: Any = None
        self.scaler: Any = None

        base_dir = Path(__file__).parent
        resolved_model_path = model_path or str(base_dir / DEFAULT_MODEL_FILENAME)
        resolved_scaler_path = scaler_path or str(base_dir / DEFAULT_SCALER_FILENAME)

        self.load_model(resolved_model_path)
        if Path(resolved_scaler_path).exists():
            self.scaler = joblib.load(resolved_scaler_path)

    @property
    def metadata(self) -> DetectorMetadata:
        return DetectorMetadata(
            name="ddos",
            version="1.0.0",
            required_features=FEATURE_NAMES
        )

    @property
    def threat_class(self) -> ThreatClass:
        return ThreatClass(
            name="VOLUMETRIC_PROTOCOL_DDOS",
            mitre_tactic="Impact (TA0040)",
            mitre_technique_id="T1498.001",
            mitre_technique_name="Direct Network Flood: SYN Flood"
        )

    def load_model(self, model_path: str) -> None:
        path = Path(model_path)
        if not path.is_absolute():
            base_dir = Path(__file__).parent
            path = base_dir / model_path

        if path.exists():
            self.model = joblib.load(path)
            scaler_candidate = path.parent / DEFAULT_SCALER_FILENAME
            if scaler_candidate.exists():
                self.scaler = joblib.load(scaler_candidate)
        else:
            raise FileNotFoundError(f"Model file not found at: {path}")

    def predict(
        self,
        features: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Optional[Prediction]:
        """
        Run inference on provided feature dictionary matching BaseThreatDetector.
        """
        if self.model is None:
            raise RuntimeError("Model is not loaded.")

        row = [features.get(col, 0.0) for col in FEATURE_NAMES]
        X = pd.DataFrame([row], columns=FEATURE_NAMES)

        if self.scaler is not None:
            X[CONTINUOUS_COLS] = self.scaler.transform(X[CONTINUOUS_COLS])

        X = X.replace([np.inf, -np.inf], np.nan).fillna(0.0)

        probability = float(self.model.predict_proba(X)[0][1])

        if probability < self.threshold:
            return None

        # Severity determination based on confidence
        if probability >= 0.9:
            severity = "CRITICAL"
        elif probability >= 0.7:
            severity = "HIGH"
        elif probability >= 0.4:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # Calculate anomaly z-score heuristic based on confidence and entropy
        entropy_val = float(features.get("source_ip_entropy_5s", 0.0))
        pps = float(features.get("packets_per_second", 0.0))
        anomaly_zscore = round(float(probability * 5.0 + min(entropy_val, 3.0) + min(pps / 10000.0, 2.0)), 2)

        evidence = {
            "packets_per_second": features.get("packets_per_second", 0.0),
            "bytes_per_second": features.get("bytes_per_second", 0.0),
            "source_ip_entropy_5s": entropy_val,
            "unique_source_ips_5s": features.get("unique_source_ips_5s", 0),
            "syn_ratio": features.get("syn_ratio", 0),
            "bidirectional_ratio": features.get("bidirectional_ratio", 0.0),
            "detection_threshold": self.threshold,
            "raw_confidence": round(probability, 4),
        }

        return Prediction(
            threat_class=self.threat_class.name,
            confidence=round(probability, 4),
            severity=severity,
            anomaly_zscore=anomaly_zscore,
            evidence=evidence
        )

    def predict_raw_event(self, raw_event: dict) -> Optional[Prediction]:
        """Convenience method to process raw flow dictionary directly."""
        features = self.window.build_features(raw_event)
        context = {
            "src_ip": raw_event.get("source") or raw_event.get("src_ip", "0.0.0.0"),
            "dst_ip": raw_event.get("destination") or raw_event.get("dst_ip", "0.0.0.0"),
        }
        return self.predict(features, context)
