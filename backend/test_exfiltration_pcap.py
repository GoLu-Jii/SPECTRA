from pathlib import Path

from backend.exfiltration_features import ExfiltrationFeatureAdapter, ExfiltrationFeatureError
from backend.exfiltration_pcap import read_exfiltration_flows
from data_and_demo.generate_demo_pcap import (
    PCAP_GLOBAL_HEADER,
    make_tcp_packet,
    write_pcap_packet,
)
from ml_engine.exfilteration.deployment import DataExfiltrationDetector


def write_flow_pcap(path: Path) -> None:
    packets = [
        (1.000000, make_tcp_packet("192.0.2.10", "198.51.100.20", 40000, 443, seq=100, flags=0x02)),
        (1.010000, make_tcp_packet("198.51.100.20", "192.0.2.10", 443, 40000, seq=900, ack=101, flags=0x12)),
        (1.020000, make_tcp_packet("192.0.2.10", "198.51.100.20", 40000, 443, seq=101, ack=901, flags=0x10)),
        (1.030000, make_tcp_packet("192.0.2.10", "198.51.100.20", 40000, 443, seq=101, ack=901, flags=0x18, payload=b"abcd")),
        (1.040000, make_tcp_packet("198.51.100.20", "192.0.2.10", 443, 40000, seq=901, ack=105, flags=0x18, payload=b"xy")),
    ]
    with path.open("wb") as handle:
        handle.write(PCAP_GLOBAL_HEADER)
        for timestamp, packet in packets:
            write_pcap_packet(handle, packet, int(timestamp), int((timestamp % 1) * 1_000_000))


def test_pcap_flow_extracts_actual_direction_counts_and_tcp_metadata(tmp_path):
    path = tmp_path / "flow.pcap"
    write_flow_pcap(path)

    events = read_exfiltration_flows(path)

    assert len(events) == 1
    event = events[0]
    metadata = event.raw["exfiltration_packet"]
    assert (event.src_ip, event.src_port) == ("192.0.2.10", 40000)
    assert (event.dst_ip, event.dst_port) == ("198.51.100.20", 443)
    assert event.orig_pkts == 4
    assert event.resp_pkts == 1
    assert event.orig_bytes == 4
    assert event.resp_bytes == 2
    assert metadata["sttl"] == 64
    assert metadata["dttl"] == 64
    assert metadata["swin"] == 64240
    assert metadata["dwin"] == 64240
    assert metadata["stcpb"] == 100
    assert metadata["dtcpb"] == 900
    assert metadata["synack"] == 0.01
    assert metadata["ackdat"] == 0.01
    assert metadata["sinpkt"] > 0
    assert metadata["sjit"] >= 0
    assert "rate" not in event.raw
    assert event.service is None
    assert event.conn_state is None


def test_pcap_event_is_rejected_without_authoritative_rate(tmp_path):
    path = tmp_path / "flow.pcap"
    write_flow_pcap(path)
    event = read_exfiltration_flows(path)[0]
    detector = DataExfiltrationDetector()

    try:
        ExfiltrationFeatureAdapter(detector.expected_features).prepare(event)
    except ExfiltrationFeatureError as exc:
        assert "rate" in str(exc)
    else:
        raise AssertionError("PCAP event without authoritative rate was accepted")


def test_incomplete_pcap_metadata_is_rejected_by_existing_adapter(tmp_path):
    path = tmp_path / "flow.pcap"
    write_flow_pcap(path)
    event = read_exfiltration_flows(path)[0]
    event.raw["rate"] = 1.0
    detector = DataExfiltrationDetector()

    try:
        ExfiltrationFeatureAdapter(detector.expected_features).prepare(event)
    except ExfiltrationFeatureError as exc:
        assert "service" in str(exc) or "conn_state" in str(exc)
    else:
        raise AssertionError("PCAP event without semantic fields was accepted")