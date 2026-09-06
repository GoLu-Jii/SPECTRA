"""Shared contract for threat detector implementations."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Any, Optional, List


@dataclass
class Prediction:
    """Detector output after inference (independent of Pydantic)."""
    threat_class: str
    confidence: float
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    anomaly_zscore: float
    evidence: Dict[str, Any]


@dataclass
class DetectorMetadata:
    """Detector self-description."""
    name: str
    version: str
    required_features: List[str]


@dataclass
class ThreatClass:
    """Threat classification with MITRE mapping."""
    name: str
    mitre_tactic: str
    mitre_technique_id: str
    mitre_technique_name: str


class BaseThreatDetector(ABC):
    """Abstract base class for all threat detectors."""

    @property
    @abstractmethod
    def metadata(self) -> DetectorMetadata:
        """Detector metadata: name, version, required_features."""
        pass

    @property
    @abstractmethod
    def threat_class(self) -> ThreatClass:
        """Threat classification this detector produces."""
        pass

    @abstractmethod
    def load_model(self, model_path: str) -> None:
        """Load serialized model from disk."""
        pass

    @abstractmethod
    def predict(self, features: Dict[str, Any], context: Dict[str, Any]) -> Optional[Prediction]:
        """
        Run inference on prepared features.

        Args:
            features: Detector-specific ML input (matching required_features).
            context: Flow identifiers and alert metadata (NOT ML input).

        Returns:
            Prediction if threat detected, None otherwise.
        """
        pass
