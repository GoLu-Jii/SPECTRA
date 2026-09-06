import importlib
from unittest.mock import Mock

from backend.ingestor import NormalizedEvent
from backend.orchestrator import FeaturePreparer, Orchestrator
from backend.windowing import WindowConfig

C2BeaconingDetector = importlib.import_module(
    "ml_engine.C2 Beaconing.c2_beaconing_detector"
).C2BeaconingDetector


def make_event(timestamp: float, uid: str, reverse: bool = False) -> NormalizedEvent:
    return NormalizedEvent(
        ts=timestamp,
        uid=uid,
        src_ip="192.0.2.10",
        src_port=40000,
        dst_ip="198.51.100.20",
        dst_port=443,
        proto="tcp",
        log_type="conn",
        orig_bytes=100,
        resp_bytes=50,
        orig_pkts=3,
        resp_pkts=2,
        raw={"flow_dir_reverse": reverse},
    )


def test_normalized_event_maps_to_c2_flow():
    event = make_event(1000.0, "C-C2-1", reverse=True)

    assert FeaturePreparer.c2_event(event) == {
        "start_time_unix": 1000.0,
        "bytes": 150,
        "pkts": 5,
        "proto": "tcp",
        "flow_dir_reverse": True,
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.20",
    }


def test_orchestrator_reaches_real_c2_detector_with_ordered_flows():
    detector = C2BeaconingDetector()
    real_predict = detector.predict
    detector.predict = Mock(wraps=real_predict)
    orchestrator = Orchestrator()
    orchestrator.register_detector(
        detector,
        WindowConfig("c2", "tumbling", 300, ["src_ip", "dst_ip"]),
    )

    first = make_event(1000.0, "C-C2-1")
    second = make_event(1010.0, "C-C2-2")
    third = make_event(1301.0, "C-C2-3")
    orchestrator.process_events([first, second, third])

    detector.predict.assert_called_once()
    flows = detector.predict.call_args.args[0]
    assert [flow["start_time_unix"] for flow in flows] == [1000.0, 1010.0]
    assert flows[0]["bytes"] == 150
    assert flows[1]["pkts"] == 5