"""Threat detector orchestration."""

import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional

from ml_engine.interface import BaseThreatDetector, Prediction
from backend.schemas import (
    Alert, FlowIdentifier, ThreatClassification, Scoring, Severity, Protocol
)
from backend.ingestor import NormalizedEvent
from backend.windowing import WindowConfig, WindowState, WindowManager


class DetectorRegistry:
    """Discovers and loads detectors at startup."""

    def __init__(self) -> None:
        self._detectors: Dict[str, BaseThreatDetector] = {}

    def register(self, detector: BaseThreatDetector) -> None:
        """Register a detector instance."""
        self._detectors[detector.metadata.name] = detector

    def get(self, name: str) -> Optional[BaseThreatDetector]:
        """Get detector by name."""
        return self._detectors.get(name)

    def all(self) -> List[BaseThreatDetector]:
        """Get all registered detectors."""
        return list(self._detectors.values())

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
        required = detector.metadata.required_features
        features: Dict[str, Any] = {}

        for feat in required:
            # Placeholder: 0.0 for all features
            # Real detectors will override this with their own logic
            features[feat] = 0.0

        return features


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

    def flush_windows(self) -> List[Alert]:
        """
        Flush all active windows and return any remaining alerts.
        Useful for testing or end-of-processing.
        """
        alerts: List[Alert] = []

        completed_windows = self.window_manager.flush_all()
        for window in completed_windows:
            for detector in self.detector_registry.all():
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
