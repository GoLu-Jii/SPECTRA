"""
DDoS Threat Detector entry point for SPECTRA ML engine.
Re-exports DDoSDetector from ddo_detector module.
"""

from ml_engine.ddos.ddo_detector import (
    DDoSDetector,
    DDoSFeatureWindow,
    FEATURE_NAMES,
    CONTINUOUS_COLS,
    PRODUCTION_THRESHOLD,
)

__all__ = [
    "DDoSDetector",
    "DDoSFeatureWindow",
    "FEATURE_NAMES",
    "CONTINUOUS_COLS",
    "PRODUCTION_THRESHOLD",
]
