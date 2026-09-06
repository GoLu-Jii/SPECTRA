"""Pydantic schemas for standardized alerts and flow identifiers."""

from pydantic import BaseModel, Field
from typing import Dict, Any
from enum import Enum
from datetime import datetime


class Severity(str, Enum):
    """Alert severity classification."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Protocol(str, Enum):
    """Network protocol types."""
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"


class FlowIdentifier(BaseModel):
    """Standardized flow context for alerts."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: Protocol


class ThreatClassification(BaseModel):
    """MITRE ATT&CK mapping for threat."""
    threat_class: str
    mitre_tactic: str
    mitre_technique_id: str
    mitre_technique_name: str


class Scoring(BaseModel):
    """Detector confidence and severity scores."""
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    severity: Severity
    anomaly_zscore: float


class Alert(BaseModel):
    """Standardized threat alert output."""
    alert_id: str
    timestamp: datetime
    flow_identifier: FlowIdentifier
    threat_classification: ThreatClassification
    scoring: Scoring
    supporting_evidence: Dict[str, Any]

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
