from unittest.mock import Mock

from backend.dns_tunnelling_pcap import DNSPacket
from backend.ingestor import NormalizedEvent
from backend.orchestrator import FeaturePreparer, Orchestrator
from backend.windowing import WindowConfig
from ml_engine.DNS_Tunelling.dns_tunnelling_detector import (
    DNSTunnellingDetector,
    FEATURE_ORDER,
)


def make_event(timestamp: float, packet: DNSPacket) -> NormalizedEvent:
    return NormalizedEvent(
        ts=timestamp,
        uid=f"DNS-{int(timestamp)}",
        src_ip=packet.src_ip,
        src_port=packet.src_port,
        dst_ip=packet.dst_ip,
        dst_port=packet.dst_port,
        proto=packet.protocol.lower(),
        log_type="dns",
        query="example.com",
        raw={"dns_packet": packet},
    )


def make_packet(timestamp: float, request: bool) -> DNSPacket:
    return DNSPacket(
        timestamp=timestamp,
        packet_length=100 if request else 140,
        original_length=100 if request else 140,
        src_ip="192.0.2.10" if request else "198.51.100.53",
        dst_ip="198.51.100.53" if request else "192.0.2.10",
        src_port=53000 if request else 53,
        dst_port=53 if request else 53000,
        protocol="UDP",
        direction="request" if request else "response",
        transaction_id=7,
        is_request=request,
        payload_length=58 if request else 98,
    )


def test_dns_uses_five_tuple_and_exact_feature_order():
    detector = DNSTunnellingDetector()
    first = make_event(1.0, make_packet(1.0, True))
    second = make_event(2.0, make_packet(2.0, False))
    first_window_event = FeaturePreparer.dns_window_event(first)
    second_window_event = FeaturePreparer.dns_window_event(second)

    assert (
        first_window_event.src_ip,
        first_window_event.src_port,
        first_window_event.dst_ip,
        first_window_event.dst_port,
    ) == (
        second_window_event.src_ip,
        second_window_event.src_port,
        second_window_event.dst_ip,
        second_window_event.dst_port,
    )

    window = Orchestrator().window_manager
    window.register_config(WindowConfig("dns_tunnelling", "tumbling", 60, ["src_ip", "dst_ip", "proto", "src_port", "dst_port"]))
    window.add_event(first_window_event, "dns_tunnelling")
    completed = window.add_event(second_window_event, "dns_tunnelling")

    assert completed == []
    features = __import__("backend.dns_tunnelling_pcap", fromlist=["build_dns_features"]).build_dns_features(
        [FeaturePreparer.dns_packet(first), FeaturePreparer.dns_packet(second)]
    )
    assert list(features) == FEATURE_ORDER
    assert detector.transform(features).shape == (1, 29)


def test_orchestrator_invokes_real_dns_detector_and_maps_positive_result():
    detector = DNSTunnellingDetector()
    detector.predict = Mock(return_value=(1, 0.95, {"evidence_key": "value"}))
    orchestrator = Orchestrator()
    orchestrator.register_detector(
        detector,
        WindowConfig("dns_tunnelling", "tumbling", 3, ["src_ip", "dst_ip", "proto", "src_port", "dst_port"]),
    )
    first = make_event(1.0, make_packet(1.0, True))
    second = make_event(3.0, make_packet(3.0, False))
    third = make_event(5.0, make_packet(5.0, True))

    alerts = orchestrator.process_events([first, second, third])

    detector.predict.assert_called_once()
    assert len(alerts) == 1
    assert alerts[0].threat_classification.threat_class == "DNS_TUNNELLING"
    assert alerts[0].scoring.severity.value == "CRITICAL"


def test_dns_flush_invokes_detector_and_maps_positive_result():
    detector = DNSTunnellingDetector()
    detector.predict = Mock(return_value=(1, 0.65, {}))
    orchestrator = Orchestrator()
    orchestrator.register_detector(
        detector,
        WindowConfig("dns_tunnelling", "tumbling", 60, ["src_ip", "dst_ip", "proto", "src_port", "dst_port"]),
    )
    orchestrator.process_events([make_event(1.0, make_packet(1.0, True))])

    alerts = orchestrator.flush_windows()

    detector.predict.assert_called_once()
    assert len(alerts) == 1
    assert alerts[0].scoring.severity.value == "MEDIUM"