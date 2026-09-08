from unittest.mock import Mock

import pytest

from backend.exfiltration_features import (
    ExfiltrationFeatureAdapter,
    ExfiltrationFeatureError,
    PACKET_FEATURES,
)
from backend.ingestor import NormalizedEvent
from backend.orchestrator import Orchestrator
from backend.schemas import Alert
from backend.windowing import WindowConfig
from ml_engine.exfilteration.deployment import DataExfiltrationDetector


def packet_metadata():
    return {
        "sttl": 64, "dttl": 60, "sloss": 0, "dloss": 0,
        "sinpkt": 0.01, "dinpkt": 0.02, "sjit": 0.001, "djit": 0.002,
        "swin": 65535, "dwin": 32768, "stcpb": 1000, "dtcpb": 2000, "tcprtt": 0.03,
        "synack": 0.01, "ackdat": 0.02,
    }


def make_event(ts=1000.0, uid="EXFIL-1", **raw):
    return NormalizedEvent(
        ts=ts,
        uid=uid,
        src_ip="192.0.2.10",
        src_port=40000,
        dst_ip="198.51.100.20",
        dst_port=443,
        proto="tcp",
        log_type="conn",
        duration=2.0,
        orig_bytes=1000,
        resp_bytes=500,
        orig_pkts=10,
        resp_pkts=5,
        service="ssl",
        conn_state="SF",
        response_body_len=0,
        raw={
            "exfiltration_packet": packet_metadata(),
            "rate": 85.5,
            "trans_depth": 1,
            "is_ftp_login": 0,
            "ct_ftp_cmd": 0,
            "ct_flw_http_mthd": 0,
            **raw,
        },
    )


def test_artifact_contract_is_authoritative():
    detector = DataExfiltrationDetector()

    assert len(detector.expected_features) == 187
    assert detector.model.n_features_in_ == 187
    assert detector.threshold == 0.3
    assert list(detector.model.classes_) == [0, 1]


def test_adapter_maps_and_derives_flow_features():
    detector = DataExfiltrationDetector()
    result = ExfiltrationFeatureAdapter(detector.expected_features).prepare(make_event())

    assert result.payload["dur"] == 2.0
    assert result.payload["spkts"] == 10.0
    assert result.payload["dpkts"] == 5.0
    assert result.payload["sbytes"] == 1000.0
    assert result.payload["dbytes"] == 500.0
    assert result.payload["rate"] == 85.5
    assert result.payload["sload"] == 4000.0
    assert result.payload["dload"] == 2000.0
    assert result.payload["smean"] == 100.0
    assert result.payload["dmean"] == 100.0
    assert result.feature_names == tuple(detector.expected_features)
    assert len(result.feature_names) == 187
    assert result.payload["proto"] == "tcp"
    assert result.payload["service"] == "ssl"
    assert result.payload["state"] == "SF"


def test_adapter_requires_real_packet_metadata():
    detector = DataExfiltrationDetector()
    adapter = ExfiltrationFeatureAdapter(detector.expected_features)
    event = make_event()
    event.raw.pop("exfiltration_packet")

    with pytest.raises(ExfiltrationFeatureError, match="packet metadata"):
        adapter.prepare(event)


def test_adapter_keeps_historical_counts_to_last_100_records():
    detector = DataExfiltrationDetector()
    adapter = ExfiltrationFeatureAdapter(detector.expected_features)

    for index in range(101):
        result = adapter.prepare(make_event(ts=1000.0 + index, uid=f"EXFIL-{index}"))

    assert result.payload["ct_src_ltm"] == 100
    assert result.payload["ct_dst_ltm"] == 100


def test_complete_payload_reaches_wrapper_without_accuracy_claim():
    detector = DataExfiltrationDetector()
    result = ExfiltrationFeatureAdapter(detector.expected_features).prepare(make_event())

    prediction = detector.predict(result.payload)

    assert len(prediction) == 1
    assert set(prediction[0]) == {"prediction", "confidence", "label"}
    assert prediction[0]["prediction"] in {0, 1}


def test_positive_prediction_becomes_standard_alert():
    detector = DataExfiltrationDetector()
    detector.predict = Mock(return_value=[
        {"prediction": 1, "confidence": 0.91, "label": "exfiltration"}
    ])
    orchestrator = Orchestrator()
    orchestrator.register_detector(
        detector, WindowConfig("exfiltration", "tumbling", 1, [])
    )

    alerts = orchestrator.process_events([make_event()])

    assert len(alerts) == 1
    assert isinstance(alerts[0], Alert)
    assert alerts[0].threat_classification.threat_class == "Data Exfiltration"
    assert alerts[0].scoring.confidence_score == 0.91
    assert alerts[0].supporting_evidence["threshold"] == 0.3
    detector.predict.assert_called_once()