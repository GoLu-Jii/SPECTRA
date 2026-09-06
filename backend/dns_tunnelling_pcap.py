"""Passive DNS packet extraction for the DNS tunnelling feature schema.

This module is intentionally independent of the orchestrator and detector. It
parses classic Ethernet PCAP records, groups DNS packets by bidirectional flow
and transaction ID, and emits the detector's exact 29-feature order.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from ipaddress import IPv4Address
from pathlib import Path
from statistics import mean, median, mode, StatisticsError, pvariance, pstdev
from typing import Dict, Iterable, List, Mapping, Tuple
import struct

import dpkt

from ml_engine.DNS_Tunelling.dns_tunnelling_detector import FEATURE_ORDER


@dataclass(frozen=True)
class DNSPacket:
    timestamp: float
    packet_length: int
    original_length: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    direction: str
    transaction_id: int
    is_request: bool
    payload_length: int


def read_dns_packets(path: str | Path) -> List[DNSPacket]:
    """Read DNS-over-UDP/TCP packets from a classic Ethernet PCAP."""
    packets: List[DNSPacket] = []
    with Path(path).open("rb") as handle:
        reader = dpkt.pcap.Reader(handle)
        linktype = reader.datalink()
        for timestamp, raw, captured_length, original_length in _records(reader):
            if linktype != dpkt.pcap.DLT_EN10MB:
                continue
            packet = _parse_dns_packet(
                timestamp,
                raw,
                captured_length,
                original_length,
            )
            if packet is not None:
                packets.append(packet)
    return packets


def group_dns_packets(packets: Iterable[DNSPacket]) -> Dict[Tuple, List[DNSPacket]]:
    """Group packets by canonical endpoints, protocol, and DNS transaction ID."""
    groups: Dict[Tuple, List[DNSPacket]] = {}
    for packet in packets:
        endpoint_a = (packet.src_ip, packet.src_port)
        endpoint_b = (packet.dst_ip, packet.dst_port)
        endpoints = tuple(sorted((endpoint_a, endpoint_b)))
        key = (endpoints, packet.protocol, packet.transaction_id)
        groups.setdefault(key, []).append(packet)
    for values in groups.values():
        values.sort(key=lambda packet: packet.timestamp)
    return groups


def build_dns_features(packets: Iterable[DNSPacket]) -> Dict[str, float]:
    """Build the exact DNS detector feature order from one grouped flow.

    Duration is the last timestamp minus the first. Flow byte totals use the
    original wire length when present and are split by request/response
    direction. Rates divide totals by duration and return zero for a zero-time
    flow. Packet-length statistics use all packet lengths.

    Packet-time samples are consecutive timestamp deltas in chronological
    order. Response-time samples are each response timestamp minus the latest
    preceding request timestamp. Variance and standard deviation are population
    statistics. Mode is the smallest value among tied modes; empty or
    single-value samples return zero for every statistic except their mean,
    median, and mode. Skew-from-median and skew-from-mode are mean minus the
    corresponding location. Median skew uses the Pearson factor of three;
    mode skew is unscaled. Coefficient of variation is standard deviation
    divided by the absolute mean, or zero when the mean is zero. Skew values
    are ``-10.0`` when standard deviation is zero. Packet-time
    coefficient of variation uses ``-1.0`` when its mean is zero; other
    feature families use ``0.0`` for that case.
    """
    ordered = sorted(packets, key=lambda packet: packet.timestamp)
    duration = max((ordered[-1].timestamp - ordered[0].timestamp), 0.0) if ordered else 0.0
    lengths = [float(packet.packet_length) for packet in ordered]
    packet_times = [
        max(current.timestamp - previous.timestamp, 0.0)
        for previous, current in zip(ordered, ordered[1:])
    ]
    response_times: List[float] = []
    latest_request: float | None = None
    for packet in ordered:
        if packet.is_request:
            latest_request = packet.timestamp
        elif latest_request is not None:
            response_times.append(max(packet.timestamp - latest_request, 0.0))

    sent = sum(float(packet.original_length) for packet in ordered if packet.is_request)
    received = sum(float(packet.original_length) for packet in ordered if not packet.is_request)
    features = {
        "Duration": duration,
        "FlowBytesSent": sent,
        "FlowSentRate": sent / duration if duration else 0.0,
        "FlowBytesReceived": received,
        "FlowReceivedRate": received / duration if duration else 0.0,
    }
    features.update(_statistics("PacketLength", lengths))
    features.update(_statistics("PacketTime", packet_times))
    features.update(_statistics("ResponseTimeTime", response_times))
    return {name: _finite(features.get(name, 0.0)) for name in FEATURE_ORDER}


def _statistics(prefix: str, values: List[float]) -> Dict[str, float]:
    if not values:
        return {
            f"{prefix}{suffix}": (
                -10.0 if suffix in ("SkewFromMedian", "SkewFromMode")
                else -1.0 if prefix == "PacketTime" and suffix == "CoefficientofVariation"
                else 0.0
            )
            for suffix in (
                "Variance", "StandardDeviation", "Mean", "Median", "Mode",
                "SkewFromMedian", "SkewFromMode", "CoefficientofVariation",
            )
        }
    average = float(mean(values))
    middle = float(median(values))
    most_common = float(_deterministic_mode(values))
    standard_deviation = float(pstdev(values))
    return {
        f"{prefix}Variance": float(pvariance(values)),
        f"{prefix}StandardDeviation": standard_deviation,
        f"{prefix}Mean": average,
        f"{prefix}Median": middle,
        f"{prefix}Mode": most_common,
        f"{prefix}SkewFromMedian": (
            3.0 * (average - middle) / standard_deviation
            if standard_deviation else -10.0
        ),
        f"{prefix}SkewFromMode": (
            (average - most_common) / standard_deviation
            if standard_deviation else -10.0
        ),
        f"{prefix}CoefficientofVariation": (
            -1.0 if prefix == "PacketTime" and average == 0
            else standard_deviation / abs(average) if average else 0.0
        ),
    }


def _deterministic_mode(values: List[float]) -> float:
    counts = Counter(values)
    highest = max(counts.values())
    return min(value for value, count in counts.items() if count == highest)


def _finite(value: float) -> float:
    return float(value) if value == value and abs(value) != float("inf") else 0.0


def _records(reader: dpkt.pcap.Reader):
    """Yield records with both captured and original lengths.

    dpkt's public Reader iterator exposes captured bytes only, so this helper
    reads its underlying classic-PCAP record headers while retaining dpkt's
    global-header/link-layer handling.
    """
    file_handle = reader._Reader__f
    file_handle.seek(24)
    file_handle.seek(24)
    order = "<" if reader._Reader__fh.magic in (0xD4C3B2A1, 0x4D3CB2A1) else ">"
    header = struct.Struct(order + "IIII")
    while True:
        raw_header = file_handle.read(header.size)
        if not raw_header or len(raw_header) < header.size:
            return
        seconds, microseconds, captured_length, original_length = header.unpack(raw_header)
        raw = file_handle.read(captured_length)
        if len(raw) < captured_length:
            return
        yield seconds + microseconds / 1_000_000.0, raw, captured_length, original_length


def _parse_dns_packet(timestamp: float, raw: bytes, captured_length: int, original_length: int) -> DNSPacket | None:
    try:
        ethernet = dpkt.ethernet.Ethernet(raw)
        ip = ethernet.data
        if not isinstance(ip, dpkt.ip.IP):
            return None
        transport = ip.data
        protocol = None
        payload = b""
        src_port = dst_port = 0
        if isinstance(transport, dpkt.udp.UDP):
            protocol = "UDP"
            src_port, dst_port, payload = transport.sport, transport.dport, bytes(transport.data)
        elif isinstance(transport, dpkt.tcp.TCP):
            protocol = "TCP"
            src_port, dst_port, payload = transport.sport, transport.dport, bytes(transport.data)
            if len(payload) >= 2:
                payload = payload[2:]
        else:
            return None
        if src_port != 53 and dst_port != 53:
            return None
        dns = dpkt.dns.DNS(payload)
        is_request = not bool(dns.qr)
        direction = "request" if is_request else "response"
        return DNSPacket(
            timestamp=timestamp,
            packet_length=captured_length,
            original_length=original_length,
            src_ip=str(IPv4Address(ip.src)),
            dst_ip=str(IPv4Address(ip.dst)),
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            direction=direction,
            transaction_id=int(dns.id),
            is_request=is_request,
            payload_length=len(payload),
        )
    except (dpkt.dpkt.UnpackError, ValueError, AttributeError, IndexError):
        return None