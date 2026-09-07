"""Threat detector orchestration."""

import uuid
import importlib
from dataclasses import replace
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

from ml_engine.interface import BaseThreatDetector, Prediction
from backend.schemas import (
    Alert, FlowIdentifier, ThreatClassification, Scoring, Severity, Protocol
)
from backend.ingestor import NormalizedEvent
from backend.windowing import WindowConfig, WindowState, WindowManager
from ml_engine.ddos.ddo_detector import DDoSDetector
from ml_engine.port_scanning.detector import PortScanDetector
from ml_engine.DNS_Tunelling.dns_tunnelling_detector import DNSTunnellingDetector
from backend.dns_tunnelling_pcap import DNSPacket, build_dns_features
from backend.malware_tls_features import MalwareTLSFeatureAdapter

C2BeaconingDetector = importlib.import_module(
    "ml_engine.C2 Beaconing.c2_beaconing_detector"
).C2BeaconingDetector
DGA_Detector = importlib.import_module(
    "ml_engine.DGA.dga_detector"
).DGADetector


class DetectorRegistry:
    """Discovers and loads detectors at startup."""

    def __init__(self) -> None:
        self._detectors: Dict[str, BaseThreatDetector] = {}

    def register(self, detector: BaseThreatDetector) -> None:
        """Register a detector instance."""
        if isinstance(detector, DDoSDetector):
            self._detectors["ddos"] = detector
            return
        if isinstance(detector, C2BeaconingDetector):
            self._detectors["c2"] = detector
            return
        if isinstance(detector, DGA_Detector):
            self._detectors["dga"] = detector
            return
        if isinstance(detector, DNSTunnellingDetector):
            self._detectors["dns_tunnelling"] = detector
            return
        if isinstance(detector, MalwareTLSFeatureAdapter):
            self._detectors["malware_tls"] = detector
            return
        self._detectors[detector.metadata.name] = detector

    def get(self, name: str) -> Optional[BaseThreatDetector]:
        """Get detector by name."""
        return self._detectors.get(name)

    def all(self) -> List[BaseThreatDetector]:
        """Get all registered detectors."""
        return list(self._detectors.values())

    def names(self) -> List[str]:
        """Get registered detector names."""
        return list(self._detectors)

    def discover_from_directory(self, directory: str) -> None:
        """
        Auto-discover detectors from ml_engine/*/detector.py.
        Placeholder for future implementation.
        """
        pass


class FeaturePreparer:
    """
    Prepares detector-specific features from window events.

    PLACEHOLDER: For now returns dummy features.
    Future P1/P2 will implement their own feature engineering
    within their detector classes or via dedicated modules.
    """

    def prepare(
        self,
        detector: BaseThreatDetector,
        window: WindowState
    ) -> Dict[str, Any]:
        """
        Extract features matching detector's required_features.

        Currently returns placeholder values.
        Real implementation will be provided by P1/P2 detectors.
        """
        if isinstance(detector, PortScanDetector):
            features: Dict[str, Any] = {}
            for event in window.events:
                features = detector.window.build_features(
                    self._port_scan_event(event)
                )
            return features

        required = detector.metadata.required_features
        features: Dict[str, Any] = {}

        for feat in required:
            # Placeholder: 0.0 for all features
            # Real detectors will override this with their own logic
            features[feat] = 0.0

        return features

    @staticmethod
    def ddos_event(event: NormalizedEvent) -> Dict[str, Any]:
        """Convert a normalized flow to the DDoS detector input shape."""
        start = datetime.fromtimestamp(event.ts)
        stop = start + timedelta(seconds=event.duration or 0.0)
        return {
            "startDateTime": start.isoformat(),
            "stopDateTime": stop.isoformat(),
            "source": event.src_ip,
            "destination": event.dst_ip,
            "protocolName": event.proto,
            "direction": event.raw.get("direction") or "L2R",
            "totalSourceBytes": event.orig_bytes or 0,
            "totalDestinationBytes": event.resp_bytes or 0,
            "totalSourcePackets": event.orig_pkts or 0,
            "totalDestinationPackets": event.resp_pkts or 0,
            "sourceTCPFlagsDescription": event.history or "",
        }

    @staticmethod
    def c2_event(event: NormalizedEvent) -> Dict[str, Any]:
        """Convert a normalized flow to the C2 detector input shape."""
        return {
            "start_time_unix": event.ts,
            "bytes": (event.orig_bytes or 0) + (event.resp_bytes or 0),
            "pkts": (event.orig_pkts or 0) + (event.resp_pkts or 0),
            "proto": event.proto,
            "flow_dir_reverse": bool(event.raw.get("flow_dir_reverse", False)),
            "src_ip": event.src_ip,
            "dst_ip": event.dst_ip,
        }

    @staticmethod
    def dns_packet(event: NormalizedEvent) -> DNSPacket:
        """Read packet-level DNS metadata preserved in a normalized event."""
        packet = event.raw.get("dns_packet")
        if isinstance(packet, DNSPacket):
            return packet
        if isinstance(packet, dict):
            return DNSPacket(**packet)
        raise ValueError("DNS event is missing raw dns_packet metadata")

    @staticmethod
    def dns_window_event(event: NormalizedEvent) -> NormalizedEvent:
        """Canonicalize DNS endpoints for directional WindowManager keys."""
        packet = FeaturePreparer.dns_packet(event)
        if packet.is_request:
            endpoints = (packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port)
        else:
            endpoints = (packet.dst_ip, packet.dst_port, packet.src_ip, packet.src_port)
        return replace(
            event,
            src_ip=endpoints[0],
            src_port=endpoints[1],
            dst_ip=endpoints[2],
            dst_port=endpoints[3],
        )

    @staticmethod
    def _port_scan_event(event: NormalizedEvent) -> Dict[str, Any]:
        """Convert a normalized flow to the Port Scan detector input shape."""
        start = datetime.fromtimestamp(event.ts)
        duration = event.duration or 0.0
        stop = start + timedelta(seconds=duration)
        return {
            "startDateTime": start.isoformat(),
            "stopDateTime": stop.isoformat(),
            "source": event.src_ip,
            "destination": event.dst_ip,
            "dst_port": event.dst_port,
            "orig_pkts": event.orig_pkts,
            "resp_pkts": event.resp_pkts,
            "history": event.history,
        }


class AlertGenerator:
    """Converts Prediction to Alert using backend/schemas.py."""

    # MITRE mapping for known threat classes
    MITRE_MAP: Dict[str, Dict[str, str]] = {
        "MOCK_THREAT": {
            "mitre_tactic": "Testing (TA9999)",
            "mitre_technique_id": "T9999.001",
            "mitre_technique_name": "Mock Detection Technique"
        }
    }

    def generate(
        self,
        prediction: Prediction,
        event: NormalizedEvent
    ) -> Alert:
        """Create Alert from Prediction + original event context."""

        # Get MITRE info from prediction evidence or fallback to map
        mitre = self.MITRE_MAP.get(prediction.threat_class, {})

        # Create alert using Pydantic models from schemas.py
        alert = Alert(
            alert_id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
            timestamp=datetime.fromtimestamp(event.ts),
            flow_identifier=FlowIdentifier(
                src_ip=event.src_ip,
                dst_ip=event.dst_ip,
                src_port=event.src_port,
                dst_port=event.dst_port,
                protocol=Protocol(event.proto.upper())
            ),
            threat_classification=ThreatClassification(
                threat_class=prediction.threat_class,
                mitre_tactic=mitre.get("mitre_tactic", "Unknown"),
                mitre_technique_id=mitre.get("mitre_technique_id", "Unknown"),
                mitre_technique_name=mitre.get("mitre_technique_name", "Unknown")
            ),
            scoring=Scoring(
                confidence_score=prediction.confidence,
                severity=Severity(prediction.severity),
                anomaly_zscore=prediction.anomaly_zscore
            ),
            supporting_evidence=prediction.evidence
        )

        return alert


class Orchestrator:
    """Main orchestration entry point."""

    def __init__(
        self,
        detector_registry: Optional[DetectorRegistry] = None,
        window_manager: Optional[WindowManager] = None,
        feature_preparer: Optional[FeaturePreparer] = None,
        alert_generator: Optional[AlertGenerator] = None
    ) -> None:
        self.detector_registry = detector_registry or DetectorRegistry()
        self.window_manager = window_manager or WindowManager()
        self.feature_preparer = feature_preparer or FeaturePreparer()
        self.alert_generator = alert_generator or AlertGenerator()

    def register_detector(
        self,
        detector: BaseThreatDetector,
        window_config: WindowConfig
    ) -> None:
        """Register detector and its window config."""
        self.detector_registry.register(detector)
        self.window_manager.register_config(window_config)

    def process_events(self, events: List[NormalizedEvent]) -> List[Alert]:
        """
        Process events through all detectors, return alerts.

        Flow:
        1. For each event
        2. For each detector
        3. Add event to window
        4. If window completes, prepare features, run predict, generate alert
        """
        alerts: List[Alert] = []

        for event in events:
            for detector in self.detector_registry.all():
                if isinstance(detector, DDoSDetector):
                    result = detector.predict(
                        self.feature_preparer.ddos_event(event)
                    )
                    prediction = self._ddos_prediction(result)
                    if prediction:
                        alerts.append(self.alert_generator.generate(prediction, event))
                    continue

                if isinstance(detector, C2BeaconingDetector):
                    completed_windows = self.window_manager.add_event(event, "c2")
                    for window in completed_windows:
                        if len(window.events) < 2:
                            continue
                        flows = sorted(
                            (self.feature_preparer.c2_event(item) for item in window.events),
                            key=lambda flow: float(flow["start_time_unix"]),
                        )
                        alert, confidence, evidence = detector.predict(flows)
                        if alert:
                            prediction = Prediction(
                                threat_class="BOTNET_C2_BEACONING",
                                confidence=float(confidence),
                                severity=self._c2_severity(float(confidence)),
                                anomaly_zscore=0.0,
                                evidence={
                                    **evidence,
                                    "src_ip": window.events[0].src_ip,
                                    "dst_ip": window.events[0].dst_ip,
                                },
                            )
                            alerts.append(self.alert_generator.generate(prediction, event))
                    continue

                if isinstance(detector, DGA_Detector):
                    if event.log_type != "dns" or not event.query:
                        continue
                    alert, confidence, evidence = detector.predict(event.query)
                    if alert:
                        prediction = Prediction(
                            threat_class="DGA_DOMAIN",
                            confidence=float(confidence),
                            severity=self._dga_severity(float(confidence)),
                            anomaly_zscore=0.0,
                            evidence={**evidence, "query": event.query},
                        )
                        alerts.append(self.alert_generator.generate(prediction, event))
                    continue

                if isinstance(detector, DNSTunnellingDetector):
                    if event.log_type != "dns":
                        continue
                    if "dns_packet" not in event.raw:
                        continue
                    window_event = self.feature_preparer.dns_window_event(event)
                    completed_windows = self.window_manager.add_event(
                        window_event, "dns_tunnelling"
                    )
                    for window in completed_windows:
                        prediction = self._dns_prediction(detector, window)
                        if prediction:
                            alerts.append(self.alert_generator.generate(prediction, event))
                    continue

                if isinstance(detector, MalwareTLSFeatureAdapter):
                    completed_windows = self.window_manager.add_event(
                        event, "malware_tls"
                    )
                    for window in completed_windows:
                        prediction = self._tls_prediction(detector, window)
                        if prediction:
                            alerts.append(self.alert_generator.generate(prediction, event))
                    continue

                # Add event to window
                completed_windows = self.window_manager.add_event(event, detector.metadata.name)

                # Process completed windows
                for window in completed_windows:
                    features = self.feature_preparer.prepare(detector, window)
                    context = self._make_context(event, window)

                    prediction = detector.predict(features, context)
                    if prediction:
                        alert = self.alert_generator.generate(prediction, event)
                        alerts.append(alert)

        return alerts

    @staticmethod
    def _ddos_prediction(result: Optional[Dict[str, Any]]) -> Optional[Prediction]:
        if not result:
            return None
        return Prediction(
            threat_class=result["label"],
            confidence=float(result["confidence"]),
            severity=result["severity"],
            anomaly_zscore=0.0,
            evidence=result["evidence"],
        )

    @staticmethod
    def _c2_severity(confidence: float) -> str:
        if confidence < 0.40:
            return "LOW"
        if confidence < 0.70:
            return "MEDIUM"
        if confidence < 0.90:
            return "HIGH"
        return "CRITICAL"

    @staticmethod
    def _dga_severity(confidence: float) -> str:
        if confidence < 0.40:
            return "LOW"
        if confidence < 0.70:
            return "MEDIUM"
        if confidence < 0.90:
            return "HIGH"
        return "CRITICAL"

    @staticmethod
    def _dns_prediction(
        detector: DNSTunnellingDetector,
        window: WindowState,
    ) -> Optional[Prediction]:
        packets = [FeaturePreparer.dns_packet(event) for event in window.events]
        features = build_dns_features(packets)
        alert, confidence, evidence = detector.predict(features)
        if not alert:
            return None
        return Prediction(
            threat_class="DNS_TUNNELLING",
            confidence=float(confidence),
            severity=Orchestrator._confidence_severity(float(confidence)),
            anomaly_zscore=0.0,
            evidence=evidence,
        )

    @staticmethod
    def _confidence_severity(confidence: float) -> str:
        if confidence < 0.40:
            return "LOW"
        if confidence < 0.70:
            return "MEDIUM"
        if confidence < 0.90:
            return "HIGH"
        return "CRITICAL"

    @staticmethod
    def _tls_prediction(
        detector: MalwareTLSFeatureAdapter,
        window: WindowState,
    ) -> Optional[Prediction]:
        features, verdict = detector.assess(window.events, window.events[-1])
        if not verdict.malware_detected:
            return None
        evidence = {
            "model_probability": verdict.probability,
            "raw_probability": verdict.stability.raw_probability,
            "probability_stddev": verdict.stability.probability_stddev,
            "decision_stability": verdict.stability.decision_stability,
            "review_reasons": list(verdict.review_reasons),
            "quic": verdict.quic,
            "model_feature_count": len(features),
        }
        return Prediction(
            threat_class="MALWARE_TLS",
            confidence=float(verdict.probability),
            severity=Orchestrator._confidence_severity(float(verdict.probability)),
            anomaly_zscore=0.0,
            evidence=evidence,
        )

    def flush_windows(self) -> List[Alert]:
        """
        Flush all active windows and return any remaining alerts.
        Useful for testing or end-of-processing.
        """
        alerts: List[Alert] = []

        completed_windows = self.window_manager.flush_all()
        for window in completed_windows:
            for detector in self.detector_registry.all():
                if isinstance(detector, DDoSDetector) or isinstance(detector, DGA_Detector):
                    continue
                if isinstance(detector, C2BeaconingDetector):
                    if window.config.detector_name != "c2" or len(window.events) < 2:
                        continue
                    flows = sorted(
                        (self.feature_preparer.c2_event(item) for item in window.events),
                        key=lambda flow: float(flow["start_time_unix"]),
                    )
                    alert, confidence, evidence = detector.predict(flows)
                    if alert and window.events:
                        prediction = Prediction(
                            threat_class="BOTNET_C2_BEACONING",
                            confidence=float(confidence),
                            severity=self._c2_severity(float(confidence)),
                            anomaly_zscore=0.0,
                            evidence={
                                **evidence,
                                "src_ip": window.events[0].src_ip,
                                "dst_ip": window.events[0].dst_ip,
                            },
                        )
                        alerts.append(
                            self.alert_generator.generate(prediction, window.events[-1])
                        )
                    continue
                if isinstance(detector, DNSTunnellingDetector):
                    if window.config.detector_name != "dns_tunnelling":
                        continue
                    prediction = self._dns_prediction(detector, window)
                    if prediction and window.events:
                        alerts.append(
                            self.alert_generator.generate(prediction, window.events[0])
                        )
                    continue
                if isinstance(detector, MalwareTLSFeatureAdapter):
                    if window.config.detector_name != "malware_tls":
                        continue
                    prediction = self._tls_prediction(detector, window)
                    if prediction and window.events:
                        alerts.append(
                            self.alert_generator.generate(prediction, window.events[-1])
                        )
                    continue
                if window.config.detector_name == detector.metadata.name:
                    features = self.feature_preparer.prepare(detector, window)
                    context = self._make_context_from_window(window)

                    prediction = detector.predict(features, context)
                    if prediction:
                        # Use first event for alert context
                        first_event = window.events[0] if window.events else None
                        if first_event:
                            alert = self.alert_generator.generate(prediction, first_event)
                            alerts.append(alert)

        return alerts

    def _make_context(
        self,
        event: NormalizedEvent,
        window: WindowState
    ) -> Dict[str, Any]:
        """Create context dict from event and window."""
        return {
            "src_ip": event.src_ip,
            "dst_ip": event.dst_ip,
            "src_port": event.src_port,
            "dst_port": event.dst_port,
            "protocol": event.proto,
            "window_id": window.window_id,
            "group_key": window.group_key,
            "window_start": window.start_time.isoformat()
        }

    def _make_context_from_window(self, window: WindowState) -> Dict[str, Any]:
        """Create context dict from window (for flush)."""
        if window.events:
            event = window.events[0]
            return {
                "src_ip": event.src_ip,
                "dst_ip": event.dst_ip,
                "src_port": event.src_port,
                "dst_port": event.dst_port,
                "protocol": event.proto,
                "window_id": window.window_id,
                "group_key": window.group_key,
                "window_start": window.start_time.isoformat()
            }
        return {
            "src_ip": "unknown",
            "dst_ip": "unknown",
            "src_port": 0,
            "dst_port": 0,
            "protocol": "tcp",
            "window_id": window.window_id,
            "group_key": window.group_key,
            "window_start": window.start_time.isoformat()
        }
