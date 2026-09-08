"""
Recon / Port Scan Threat Detector for SPECTRA.

Model:
    XGBoost PortScan classifier

Model input:
    5 flow-level features

Detector behavior:
    Hybrid ML + 60-second port scanning heuristics

The XGBoost model itself is stateless.
The detector maintains a 60-second rolling window per source IP
to generate contextual evidence and strengthen detections.
"""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta
from pathlib import Path
from typing import Dict, Any, Optional

import joblib
import numpy as np
import pandas as pd

from ml_engine.interface import (
    BaseThreatDetector,
    DetectorMetadata,
    ThreatClass,
    Prediction,
)


# Exact features used to train model_ps3 in port_scan_model.ipynb.
# Order must remain unchanged.
FEATURE_NAMES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "FIN Flag Count",
    "Destination Port",
]

DEFAULT_MODEL_FILENAME = "portscan_model.pkl"

# Application-level detector threshold.
# Not a training parameter from XGBoost.
PRODUCTION_THRESHOLD = 0.3

# Contextual port-scan window size.
WINDOW_SECONDS = 60


class PortScanFeatureWindow:
    """
    Stateful 60-second feature aggregator grouped by source IP.

    Window features are NOT XGBoost model inputs.
    They are used for contextual evidence and heuristic detection.
    """

    def __init__(self) -> None:
        self.events: Dict[str, deque] = defaultdict(deque)

    def build_features(self, event: dict) -> dict:
        """
        Convert a raw network flow event into:
        1. The 5 exact XGBoost model features.
        2. Additional 60-second contextual features.
        """
        event = dict(event)

        start = pd.to_datetime(
            event.get("startDateTime")
            or event.get("ts")
            or "now"
        )

        stop = pd.to_datetime(
            event.get("stopDateTime")
            or start
        )

        src_ip = (
            event.get("source")
            or event.get("src_ip")
            or "0.0.0.0"
        )

        dst_ip = (
            event.get("destination")
            or event.get("dst_ip")
            or "0.0.0.0"
        )

        dst_port = float(
            event.get(
                "dst_port",
                event.get("id.resp_p", 80)
            )
        )

        fwd_pkts = float(
            event.get(
                "totalSourcePackets",
                event.get("orig_pkts", 1)
            )
            or 0
        )

        bwd_pkts = float(
            event.get(
                "totalDestinationPackets",
                event.get("resp_pkts", 0)
            )
            or 0
        )

        flags = str(
            event.get("sourceTCPFlagsDescription")
            or event.get("history")
            or ""
        )

        fin_flag = int("F" in flags or "f" in flags)
        syn_flag = int("S" in flags or "s" in flags)
        ack_flag = int("A" in flags or "a" in flags)

        duration_seconds = max(
            (stop - start).total_seconds(),
            0.000001
        )

        # CICIDS-style Flow Duration is in microseconds.
        flow_duration_us = duration_seconds * 1_000_000.0

        base_event = {
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

        queue = self.events[src_ip]
        cutoff = start - timedelta(seconds=WINDOW_SECONDS)

        while queue and queue[0]["timestamp"] < cutoff:
            queue.popleft()

        queue.append(base_event)
        events_60s = list(queue)

        unique_dst_ports = len({
            item["dst_port"]
            for item in events_60s
        })

        unique_dst_ips = len({
            item["dst_ip"]
            for item in events_60s
        })

        syn_only = sum(
            1
            for item in events_60s
            if item["syn_flag"] == 1
            and item["ack_flag"] == 0
        )

        unanswered_syn_ratio = (
            syn_only / max(len(events_60s), 1)
        )

        avg_flow_duration_ms = (
            sum(
                item["flow_duration_us"]
                for item in events_60s
            )
            / max(len(events_60s), 1)
        ) / 1000.0

        if unique_dst_ports > 10 and unique_dst_ips == 1:
            scan_type = "TCP Vertical Port Scan"

        elif unique_dst_ips > 10 and unique_dst_ports <= 3:
            scan_type = "TCP Horizontal Sweep"

        elif unique_dst_ports > 5 or unique_dst_ips > 5:
            scan_type = "Distributed Port Scan"

        else:
            scan_type = "Probing Activity"

        return {
            # Exact XGBoost model features.
            "Flow Duration": flow_duration_us,
            "Total Fwd Packets": fwd_pkts,
            "Total Backward Packets": bwd_pkts,
            "FIN Flag Count": fin_flag,
            "Destination Port": dst_port,

            # Contextual features.
            # NOT model inputs.
            "unique_dst_ports_60s": unique_dst_ports,
            "unique_dst_ips_60s": unique_dst_ips,
            "unanswered_syn_ratio": unanswered_syn_ratio,
            "avg_flow_duration_ms": avg_flow_duration_ms,
            "scan_type": scan_type,
        }


class PortScanDetector(BaseThreatDetector):
    """
    Recon / Port Scan detector.

    Architecture:

        Raw Flow
            |
            v
        PortScanFeatureWindow
            |
            +--> 5 model features
            |
            +--> 60-second evidence features
            |
            v
        XGBoost Model
            |
            v
        Model Probability + Window Heuristic
            |
            v
        Final Detection
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

        resolved_model_path = (
            model_path
            or str(base_dir / DEFAULT_MODEL_FILENAME)
        )

        self.load_model(resolved_model_path)

    @property
    def metadata(self) -> DetectorMetadata:
        return DetectorMetadata(
            name="recon",
            version="1.0.0",
            required_features=FEATURE_NAMES,
        )

    @property
    def threat_class(self) -> ThreatClass:
        return ThreatClass(
            name="RECON_PORT_SCAN",
            mitre_tactic="Discovery (TA0007)",
            mitre_technique_id="T1046",
            mitre_technique_name="Network Service Discovery",
        )

    def load_model(self, model_path: str) -> None:
        path = Path(model_path)

        if not path.is_absolute():
            path = Path(__file__).parent / path

        if path.exists():
            self.model = joblib.load(path)
        else:
            raise FileNotFoundError(
                f"Port scan model file not found at: {path}"
            )

    def prepare_input(
        self,
        features: Dict[str, Any],
    ) -> pd.DataFrame:

        row = [
            features.get(feature, 0.0)
            for feature in FEATURE_NAMES
        ]

        X = pd.DataFrame(
            [row],
            columns=FEATURE_NAMES,
        )

        X = X.replace(
            [np.inf, -np.inf],
            np.nan,
        )

        X = X.fillna(0.0)

        return X

    def predict(
        self,
        features: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Optional[Prediction]:

        if self.model is None:
            raise RuntimeError(
                "Port scan model is not loaded."
            )

        X = self.prepare_input(features)

        probability = float(
            self.model.predict_proba(X)[0][1]
        )

        unique_ports = float(
            features.get(
                "unique_dst_ports_60s",
                0,
            )
        )

        # Hybrid detection:
        # Model probability OR significant port activity.
        if (
            probability < self.threshold
            and unique_ports < 5
        ):
            return None

        window_confidence = min(
            unique_ports / 20.0,
            0.99,
        )

        effective_confidence = max(
            probability,
            window_confidence,
        )

        if effective_confidence < self.threshold:
            return None

        if effective_confidence >= 0.90:
            severity = "HIGH"

        elif effective_confidence >= 0.70:
            severity = "MEDIUM"

        else:
            severity = "LOW"

        # Application-level anomaly score.
        anomaly_zscore = round(
            float(
                effective_confidence * 4.0
                + min(
                    unique_ports / 10.0,
                    3.0,
                )
            ),
            2,
        )

        evidence = {
            "source_ip": context.get("src_ip"),
            "destination_ip": context.get("dst_ip"),

            "destination_port": int(
                features.get(
                    "Destination Port",
                    0,
                )
            ),

            "unique_dst_ports_60s": int(
                features.get(
                    "unique_dst_ports_60s",
                    1,
                )
            ),

            "unique_dst_ips_60s": int(
                features.get(
                    "unique_dst_ips_60s",
                    1,
                )
            ),

            "unanswered_syn_ratio": round(
                float(
                    features.get(
                        "unanswered_syn_ratio",
                        0.0,
                    )
                ),
                2,
            ),

            "avg_flow_duration_ms": round(
                float(
                    features.get(
                        "avg_flow_duration_ms",
                        0.0,
                    )
                ),
                2,
            ),

            "scan_type": str(
                features.get(
                    "scan_type",
                    "Port Scan Probe",
                )
            ),

            "detection_threshold": self.threshold,

            # Raw XGBoost probability.
            "raw_model_confidence": round(
                probability,
                4,
            ),

            # Window-based confidence.
            "window_confidence": round(
                window_confidence,
                4,
            ),
        }

        return Prediction(
            threat_class=self.threat_class.name,

            confidence=round(
                effective_confidence,
                4,
            ),

            severity=severity,

            anomaly_zscore=anomaly_zscore,

            evidence=evidence,
        )

    def predict_raw_event(
        self,
        raw_event: dict,
    ) -> Optional[Prediction]:

        features = self.window.build_features(
            raw_event
        )

        context = {
            "src_ip": (
                raw_event.get("source")
                or raw_event.get(
                    "src_ip",
                    "0.0.0.0",
                )
            ),

            "dst_ip": (
                raw_event.get("destination")
                or raw_event.get(
                    "dst_ip",
                    "0.0.0.0",
                )
            ),
        }

        return self.predict(
            features,
            context,
        )