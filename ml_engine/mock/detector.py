"""Minimal mock detector for testing the BaseThreatDetector interface."""

from ml_engine.interface import BaseThreatDetector, DetectorMetadata, ThreatClass, Prediction
from typing import Dict, Any, Optional


class MockDetector(BaseThreatDetector):
    """Simple mock detector that always returns a threat."""

    @property
    def metadata(self) -> DetectorMetadata:
        return DetectorMetadata(
            name="mock",
            version="1.0.0",
            required_features=["feature_a", "feature_b", "feature_c"]
        )

    @property
    def threat_class(self) -> ThreatClass:
        return ThreatClass(
            name="MOCK_THREAT",
            mitre_tactic="Testing (TA9999)",
            mitre_technique_id="T9999.001",
            mitre_technique_name="Mock Detection Technique"
        )

    def load_model(self, model_path: str) -> None:
        """Mock detector has no model to load."""
        pass

    def predict(self, features: Dict[str, Any], context: Dict[str, Any]) -> Optional[Prediction]:
        """Always return a mock threat for testing."""
        return Prediction(
            threat_class=self.threat_class.name,
            confidence=0.95,
            severity="MEDIUM",
            anomaly_zscore=3.5,
            evidence={
                "reason": "Mock detector for testing",
                "src_ip": context.get("src_ip", "UNKNOWN"),
                "dst_ip": context.get("dst_ip", "UNKNOWN"),
            }
        )
