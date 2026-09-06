from datetime import datetime

from backend.ingestor import NormalizedEvent
from backend.orchestrator import FeaturePreparer, Orchestrator
from backend.windowing import WindowConfig, WindowState
from ml_engine.port_scanning.detector import PortScanDetector


def make_event() -> NormalizedEvent:
    return NormalizedEvent(
        ts=datetime(2026, 9, 6, 12, 0, 0).timestamp(),
        uid="C-PORT-1",
        src_ip="192.0.2.10",
        src_port=40000,
        dst_ip="198.51.100.20",
        dst_port=22,
        proto="tcp",
        log_type="conn",
        duration=1.25,
        orig_pkts=3,
        resp_pkts=2,
        history="F",
    )


def test_feature_preparer_builds_port_scan_model_inputs():
    detector = PortScanDetector()
    event = make_event()
    window = WindowState(
        window_id="win-port-test",
        config=WindowConfig("recon", "tumbling", 60, ["src_ip"]),
        group_key=event.src_ip,
        start_time=datetime.fromtimestamp(event.ts),
        events=[event],
    )

    features = FeaturePreparer().prepare(detector, window)

    assert features["Flow Duration"] == 1_250_000.0
    assert features["Total Fwd Packets"] == 3.0
    assert features["Total Backward Packets"] == 2.0
    assert features["FIN Flag Count"] == 1
    assert features["Destination Port"] == 22.0


def test_orchestrator_processes_real_port_scan_detector():
    detector = PortScanDetector()
    first = make_event()
    second = NormalizedEvent(
        **{**first.__dict__, "ts": first.ts + 2.0, "uid": "C-PORT-2"}
    )
    orchestrator = Orchestrator()
    orchestrator.register_detector(
        detector,
        WindowConfig("recon", "tumbling", 1, ["src_ip"]),
    )

    alerts = orchestrator.process_events([first, second])
    alerts.extend(orchestrator.flush_windows())

    assert isinstance(alerts, list)