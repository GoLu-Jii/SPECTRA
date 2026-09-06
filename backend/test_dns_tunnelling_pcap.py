from backend.dns_tunnelling_pcap import DNSPacket, build_dns_features, group_dns_packets
from ml_engine.DNS_Tunelling.dns_tunnelling_detector import FEATURE_ORDER


def packet(timestamp, length, request):
    return DNSPacket(
        timestamp=timestamp,
        packet_length=length,
        original_length=length,
        src_ip="192.0.2.10" if request else "198.51.100.53",
        dst_ip="198.51.100.53" if request else "192.0.2.10",
        src_port=53000 if request else 53,
        dst_port=53 if request else 53000,
        protocol="UDP",
        direction="request" if request else "response",
        transaction_id=7,
        is_request=request,
        payload_length=length - 42,
    )


def test_dns_features_preserve_exact_order_and_definitions():
    packets = [
        packet(1.0, 100, True),
        packet(2.0, 140, False),
        packet(3.0, 160, True),
        packet(5.0, 180, False),
    ]
    features = build_dns_features(packets)

    assert list(features) == FEATURE_ORDER
    assert features["Duration"] == 4.0
    assert features["FlowBytesSent"] == 260.0
    assert features["FlowBytesReceived"] == 320.0
    assert features["PacketLengthMean"] == 145.0
    assert features["PacketLengthMedian"] == 150.0
    assert features["PacketLengthMode"] == 100.0
    assert features["PacketLengthSkewFromMedian"] == 3.0 * (145.0 - 150.0) / features["PacketLengthStandardDeviation"]
    assert features["PacketLengthSkewFromMode"] == (145.0 - 100.0) / features["PacketLengthStandardDeviation"]
    assert features["PacketTimeMean"] == 4.0 / 3.0
    assert features["ResponseTimeTimeMean"] == 1.5
    assert features["ResponseTimeTimeSkewFromMedian"] == 3.0 * (1.5 - 1.5) / 0.5
    assert features["ResponseTimeTimeSkewFromMode"] == (1.5 - 1.0) / 0.5
    assert all(value == value and abs(value) != float("inf") for value in features.values())


def test_empty_and_single_packet_samples_are_deterministic():
    empty = build_dns_features([])
    single = build_dns_features([packet(1.0, 100, True)])

    assert list(empty) == FEATURE_ORDER
    assert empty["PacketLengthSkewFromMedian"] == -10.0
    assert empty["PacketLengthSkewFromMode"] == -10.0
    assert empty["PacketLengthCoefficientofVariation"] == 0.0
    assert empty["PacketTimeSkewFromMedian"] == -10.0
    assert empty["PacketTimeSkewFromMode"] == -10.0
    assert empty["PacketTimeCoefficientofVariation"] == -1.0
    assert empty["ResponseTimeTimeSkewFromMedian"] == -10.0
    assert empty["ResponseTimeTimeSkewFromMode"] == -10.0
    assert empty["ResponseTimeTimeCoefficientofVariation"] == 0.0
    assert single["PacketLengthMean"] == 100.0
    assert single["PacketLengthVariance"] == 0.0
    assert single["PacketLengthSkewFromMedian"] == -10.0
    assert single["PacketLengthSkewFromMode"] == -10.0
    assert single["PacketLengthCoefficientofVariation"] == 0.0
    assert single["PacketTimeMean"] == 0.0
    assert single["PacketTimeSkewFromMedian"] == -10.0
    assert single["PacketTimeSkewFromMode"] == -10.0
    assert single["PacketTimeCoefficientofVariation"] == -1.0
    assert single["ResponseTimeTimeMean"] == 0.0
    assert single["ResponseTimeTimeSkewFromMedian"] == -10.0
    assert single["ResponseTimeTimeSkewFromMode"] == -10.0
    assert single["ResponseTimeTimeCoefficientofVariation"] == 0.0


def test_grouping_uses_flow_and_dns_transaction_identity():
    values = [packet(1.0, 100, True), packet(2.0, 140, False)]
    groups = group_dns_packets(values)

    assert len(groups) == 1
    assert [item.transaction_id for item in next(iter(groups.values()))] == [7, 7]