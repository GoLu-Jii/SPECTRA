from datetime import datetime
from unittest.mock import Mock

import pandas as pd

from backend.ingestor import NormalizedEvent
from backend.orchestrator import FeaturePreparer, Orchestrator
from backend.windowing import WindowConfig
from ml_engine.ddos.ddo_detector import DDoSDetector, DDoSFeatureWindow


def make_event() -> NormalizedEvent:
    return NormalizedEvent(
        ts=datetime(2026, 9, 6, 12, 0, 0).timestamp(),
        uid="C-DDOS-1",
        src_ip="192.0.2.10",
        src_port=40000,
        dst_ip="198.51.100.20",
        dst_port=443,
        proto="tcp_ip",
        log_type="conn",
        duration=1.25,
        orig_bytes=100,
        resp_bytes=50,
        orig_pkts=3,
        resp_pkts=2,
        history="S",
        raw={"direction": "R2L"},
    )


def test_normalized_event_maps_to_ddos_raw_event():
    raw = FeaturePreparer.ddos_event(make_event())

    assert raw == {
        "startDateTime": "2026-09-06T12:00:00",
        "stopDateTime": "2026-09-06T12:00:01.250000",
        "source": "192.0.2.10",
        "destination": "198.51.100.20",
        "protocolName": "tcp_ip",
        "direction": "R2L",
        "totalSourceBytes": 100,
        "totalDestinationBytes": 50,
        "totalSourcePackets": 3,
        "totalDestinationPackets": 2,
        "sourceTCPFlagsDescription": "S",
    }


def test_real_ddos_model_and_scaler_reach_prediction():
    detector = DDoSDetector()
    result = detector.predict(FeaturePreparer.ddos_event(make_event()))

    assert type(detector.model).__name__ == "XGBClassifier"
    assert type(detector.scaler).__name__ == "RobustScaler"
    assert result is None or result["detector"] == "DDoSDetector"


def test_cleanup_preserves_rolling_bucket_defaultdicts():
    window = DDoSFeatureWindow()
    destination = "198.51.100.20"
    current_time = pd.Timestamp("2026-09-06T12:10:00")

    window.cleanup(destination, current_time)

    window.events_5s[destination][pd.Timestamp("2026-09-06T12:10:00")].append(1)
    window.events_30s[destination][pd.Timestamp("2026-09-06T12:10:00")].append(1)
    window.events_60s[destination][pd.Timestamp("2026-09-06T12:10:00")].append(1)


def test_orchestrator_invokes_real_ddos_detector():
    orchestrator = Orchestrator()
    detector = DDoSDetector()
    real_predict = detector.predict
    def observe(raw_event):
        real_predict(raw_event)
        return None

    detector.predict = Mock(side_effect=observe)
    orchestrator.register_detector(
        detector,
        WindowConfig("ddos", "tumbling", 60, ["dst_ip"]),
    )

    orchestrator.process_events([make_event()])

    detector.predict.assert_called_once()
    raw_event = detector.predict.call_args.args[0]
    assert raw_event["direction"] == "R2L"
    assert raw_event["totalSourceBytes"] == 100
    assert raw_event["totalDestinationPackets"] == 2