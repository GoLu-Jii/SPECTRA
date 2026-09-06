"""
Recon / Port Scan Threat Detector implementing BaseThreatDetector contract for SPECTRA.
Derived from XGBoost classifier in port_scan_model.ipynb.
"""

from __future__ import annotations

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

# 5 exact features expected by portscan_model.pkl
FEATURE_NAMES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "FIN Flag Count",
    "Destination Port",
]

DEFAULT_MODEL_FILENAME = "portscan_model.pkl"
PRODUCTION_THRESHOLD = 0.3


class PortScanFeatureWindow:
    """
    Stateful feature aggregator that tracks 60-second window metrics per source IP
    to calculate port scanning heuristics and evidence.
    """

    def __init__(self) -> None:
        self.events: Dict[str, deque] = defaultdict(deque)

    def build_features(self, event: dict) -> dict:
        event = dict(event)

        start = pd.to_datetime(event.get("startDateTime") or event.get("ts", "now"))
        stop = pd.to_datetime(event.get("stopDateTime") or start)

        src_ip = event.get("source") or event.get("src_ip") or "0.0.0.0"
        dst_ip = event.get("destination") or event.get("dst_ip") or "0.0.0.0"
        dst_port = float(event.get("dst_port", event.get("id.resp_p", 80)))

        fwd_pkts = float(event.get("totalSourcePackets", event.get("orig_pkts", 1)))
        bwd_pkts = float(event.get("totalDestinationPackets", event.get("resp_pkts", 0)))

        flags = str(event.get("sourceTCPFlagsDescription") or event.get("history") or "")
        fin_flag = int("F" in flags or "f" in flags)
        syn_flag = int("S" in flags or "s" in flags)
        ack_flag = int("A" in flags or "a" in flags)

        duration_sec = max((stop - start).total_seconds(), 0.000001)
        flow_duration_us = duration_sec * 1_000_000.0

        base = {
            "timestamp": start,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "flow_duration_us": flow_duration_us,
            "fwd_pkts": fwd_pkts,
            "bwd_pkts": bwd_pkts,
            "fin_flag": fin_flag,
            "syn_flag": syn_flag,
            "ack_flag": ack_flag,
        }

        q = self.events[src_ip]
        cutoff = start - timedelta(seconds=60)
        while q and q[0]["timestamp"] < cutoff:
            q.popleft()

        q.append(base)

        events_60 = list(q)
        unique_ports = len({e["dst_port"] for e in events_60})
        unique_ips = len({e["dst_ip"] for e in events_60})
        syn_only = sum(1 for e in events_60 if e["syn_flag"] == 1 and e["ack_flag"] == 0)

        # Categorize scan pattern
        if unique_ports > 10 and unique_ips == 1:
            scan_type = "TCP Vertical Port Scan"
        elif unique_ips > 10 and unique_ports <= 3:
            scan_type = "TCP Horizontal Sweep"
        elif unique_ports > 5 or unique_ips > 5:
            scan_type = "Distributed Port Scan"
        else:
            scan_type = "Probing Activity"

        return {
            # Direct model input features
            "Flow Duration": flow_duration_us,
            "Total Fwd Packets": fwd_pkts,
            "Total Backward Packets": bwd_pkts,
            "FIN Flag Count": fin_flag,
            "Destination Port": dst_port,
            # Contextual window features for evidence
            "unique_dst_ports_60s": unique_ports,
            "unique_dst_ips_60s": unique_ips,
            "unanswered_syn_ratio": syn_only / max(len(events_60), 1),
            "avg_flow_duration_ms": (sum(e["flow_duration_us"] for e in events_60) / len(events_60)) / 1000.0,
            "scan_type": scan_type,
        }


class PortScanDetector(BaseThreatDetector):
    """
    Port Scan Threat Detector implementing BaseThreatDetector contract.
    Loads trained XGBoost model for recon / port scan inference.
    """

    def __init__(
        self,
        model_path: Optional[str] = None,
        threshold: float = PRODUCTION_THRESHOLD,
    ) -> None:
        self.threshold = float(threshold)
        self.window = PortScanFeatureWindow()
        self.model: Any = None

        base_dir = Path(__file__).parent
        resolved_model_path = model_path or str(base_dir / DEFAULT_MODEL_FILENAME)
        self.load_model(resolved_model_path)

    @property
    def metadata(self) -> DetectorMetadata:
        return DetectorMetadata(
            name="recon",
            version="1.0.0",
            required_features=FEATURE_NAMES
        )

    @property
    def threat_class(self) -> ThreatClass:
        return ThreatClass(
            name="RECON_PORT_SCAN",
            mitre_tactic="Discovery (TA0007)",
            mitre_technique_id="T1046",
            mitre_technique_name="Network Service Discovery"
        )

    def load_model(self, model_path: str) -> None:
        path = Path(model_path)
        if not path.is_absolute():
            base_dir = Path(__file__).parent
            path = base_dir / model_path

        if path.exists():
            self.model = joblib.load(path)
        else:
            raise FileNotFoundError(f"Port scan model file not found at: {path}")

    def predict(
        self,
        features: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Optional[Prediction]:
        """
        Run inference on provided feature dictionary matching BaseThreatDetector.
        """
        if self.model is None:
            raise RuntimeError("Port scan model is not loaded.")

        row = [features.get(col, 0.0) for col in FEATURE_NAMES]
        X = pd.DataFrame([row], columns=FEATURE_NAMES)
        X = X.replace([np.inf, -np.inf], np.nan).fillna(0.0)

        probability = float(self.model.predict_proba(X)[0][1])

        # If probability or high unique dst ports ratio indicates scanning
        unique_ports = float(features.get("unique_dst_ports_60s", 0))
        if probability < self.threshold and unique_ports < 5:
            return None

        # Effective confidence elevated if windowing shows clear scanning pattern
        effective_conf = max(probability, min(unique_ports / 20.0, 0.99))

        if effective_conf < self.threshold:
            return None

        if effective_conf >= 0.9:
            severity = "HIGH"
        elif effective_conf >= 0.7:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        anomaly_zscore = round(float(effective_conf * 4.0 + min(unique_ports / 10.0, 3.0)), 2)

        evidence = {
            "unique_dst_ports_60s": int(features.get("unique_dst_ports_60s", 1)),
            "unique_dst_ips_60s": int(features.get("unique_dst_ips_60s", 1)),
            "unanswered_syn_ratio": round(float(features.get("unanswered_syn_ratio", 0.0)), 2),
            "avg_flow_duration_ms": round(float(features.get("avg_flow_duration_ms", 0.0)), 2),
            "destination_port": int(features.get("Destination Port", 0)),
            "scan_type": str(features.get("scan_type", "Port Scan Probe")),
            "detection_threshold": self.threshold,
            "raw_confidence": round(probability, 4),
        }

        return Prediction(
            threat_class=self.threat_class.name,
            confidence=round(effective_conf, 4),
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
