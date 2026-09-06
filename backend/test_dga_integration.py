import importlib
from datetime import datetime
from unittest.mock import Mock

from backend.ingestor import NormalizedEvent
from backend.orchestrator import Orchestrator
from backend.windowing import WindowConfig

DGA_Detector = importlib.import_module("ml_engine.DGA.dga_detector").DGADetector


def make_dns_event(query: str | None, log_type: str = "dns") -> NormalizedEvent:
    return NormalizedEvent(
        ts=datetime(2026, 9, 6, 12, 0, 0).timestamp(),
        uid="C-DGA-1",
        src_ip="192.0.2.10",
        src_port=53000,
        dst_ip="198.51.100.53",
        dst_port=53,
        proto="udp",
        log_type=log_type,
        query=query,
    )


def test_dga_artifacts_build_model_compatible_features():
    detector = DGA_Detector()
    features = detector.transform(["mortiscontrastatim.com"])

    assert type(detector.vectorizer).__name__ == "TfidfVectorizer"
    assert isinstance(detector.english_dict, set)
    assert features.shape == (1, 23)
    assert list(features.columns) == [str(name) for name in detector.model.feature_names_in_]


def test_orchestrator_invokes_real_dga_detector_with_query():
    detector = DGA_Detector()
    real_predict = detector.predict
    detector.predict = Mock(wraps=real_predict)
    orchestrator = Orchestrator()
    orchestrator.register_detector(detector, WindowConfig("dga", "tumbling", 1, []))

    event = make_dns_event("mortiscontrastatim.com")
    alerts = orchestrator.process_events([event])

    detector.predict.assert_called_once_with(event.query)
    assert isinstance(alerts, list)


def test_orchestrator_skips_non_dns_or_missing_query():
    detector = DGA_Detector()
    detector.predict = Mock(wraps=detector.predict)
    orchestrator = Orchestrator()
    orchestrator.register_detector(detector, WindowConfig("dga", "tumbling", 1, []))

    orchestrator.process_events([
        make_dns_event(None),
        make_dns_event("example.com", log_type="conn"),
    ])

    detector.predict.assert_not_called()