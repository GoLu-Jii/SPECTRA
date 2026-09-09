"""Passive PCAP flow conversion for Data Exfiltration feature preparation."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import dpkt

from backend.ingestor import NormalizedEvent


@dataclass
class _Flow:
    first_ts: float
    last_ts: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str
    packets: List[Dict[str, Any]] = field(default_factory=list)


def read_exfiltration_flows(path: str | Path) -> List[NormalizedEvent]:
    """Parse passive Ethernet PCAP flows into strict NormalizedEvent records.

    Packet-derived values are retained under ``raw['exfiltration_packet']``.
    The UNSW ``rate`` feature and application semantics are intentionally not
    added because this repository has no authoritative source for them.
    """
    flows: Dict[Tuple[Tuple[str, int], Tuple[str, int], str], _Flow] = {}
    with Path(path).open("rb") as handle:
        for timestamp, raw in dpkt.pcap.Reader(handle):
            packet = _parse_packet(float(timestamp), raw)
            if packet is None:
                continue
            key, source = _flow_key(packet)
            flow = flows.get(key)
            if flow is None:
                flow = _Flow(
                    first_ts=source["timestamp"],
                    last_ts=source["timestamp"],
                    src_ip=source["src_ip"],
                    dst_ip=source["dst_ip"],
                    src_port=source["src_port"],
                    dst_port=source["dst_port"],
                    proto=source["proto"],
                )
                flows[key] = flow
            flow.last_ts = source["timestamp"]
            flow.packets.append(source)

    return [_to_event(uid=f"PCAP-{index}", flow=flow) for index, flow in enumerate(flows.values(), 1)]


def _parse_packet(timestamp: float, raw: bytes) -> Dict[str, Any] | None:
    try:
        ethernet = dpkt.ethernet.Ethernet(raw)
        ip = ethernet.data
        if not isinstance(ip, dpkt.ip.IP):
            return None
        transport = ip.data
        if isinstance(transport, dpkt.tcp.TCP):
            proto = "tcp"
            src_port, dst_port = transport.sport, transport.dport
            payload = bytes(transport.data)
            return {
                "timestamp": timestamp,
                "src_ip": _ip_text(ip.src),
                "dst_ip": _ip_text(ip.dst),
                "src_port": src_port,
                "dst_port": dst_port,
                "proto": proto,
                "ttl": int(ip.ttl),
                "packet_length": len(raw),
                "payload_length": len(payload),
                "seq": int(transport.seq),
                "ack": int(transport.ack),
                "window": int(transport.win),
                "flags": int(transport.flags),
            }
        if isinstance(transport, dpkt.udp.UDP):
            return {
                "timestamp": timestamp,
                "src_ip": _ip_text(ip.src),
                "dst_ip": _ip_text(ip.dst),
                "src_port": transport.sport,
                "dst_port": transport.dport,
                "proto": "udp",
                "ttl": int(ip.ttl),
                "packet_length": len(raw),
                "payload_length": len(bytes(transport.data)),
            }
    except (dpkt.dpkt.UnpackError, ValueError, AttributeError, IndexError):
        return None
    return None


def _flow_key(packet: Dict[str, Any]):
    endpoint_a = (packet["src_ip"], packet["src_port"])
    endpoint_b = (packet["dst_ip"], packet["dst_port"])
    return (tuple(sorted((endpoint_a, endpoint_b))), packet["proto"]), packet


def _to_event(uid: str, flow: _Flow) -> NormalizedEvent:
    packets = sorted(flow.packets, key=lambda item: item["timestamp"])
    forward = [packet for packet in packets if _is_forward(packet, flow)]
    reverse = [packet for packet in packets if not _is_forward(packet, flow)]
    forward_bytes = sum(packet["payload_length"] for packet in forward)
    reverse_bytes = sum(packet["payload_length"] for packet in reverse)
    packet_metadata = _packet_metadata(packets, forward, reverse, flow.proto)

    return NormalizedEvent(
        ts=flow.first_ts,
        uid=uid,
        src_ip=flow.src_ip,
        src_port=flow.src_port,
        dst_ip=flow.dst_ip,
        dst_port=flow.dst_port,
        proto=flow.proto,
        log_type="conn",
        duration=flow.last_ts - flow.first_ts,
        orig_bytes=forward_bytes,
        resp_bytes=reverse_bytes,
        orig_pkts=len(forward),
        resp_pkts=len(reverse),
        raw={"exfiltration_packet": packet_metadata},
    )


def _is_forward(packet: Dict[str, Any], flow: _Flow) -> bool:
    return (
        packet["src_ip"], packet["src_port"], packet["dst_ip"], packet["dst_port"]
    ) == (flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port)


def _packet_metadata(
    packets: List[Dict[str, Any]],
    forward: List[Dict[str, Any]],
    reverse: List[Dict[str, Any]],
    proto: str,
) -> Dict[str, Any]:
    values: Dict[str, Any] = {}
    if forward:
        values.update({
            "sttl": forward[0]["ttl"],
            "swin": forward[0].get("window"),
            "stcpb": forward[0].get("seq"),
        })
    if reverse:
        values.update({
            "dttl": reverse[0]["ttl"],
            "dwin": reverse[0].get("window"),
            "dtcpb": reverse[0].get("seq"),
        })
    if proto == "tcp":
        _add_tcp_timing(values, packets, forward, reverse)
    return {key: value for key, value in values.items() if value is not None}


def _add_tcp_timing(
    values: Dict[str, Any],
    packets: List[Dict[str, Any]],
    forward: List[Dict[str, Any]],
    reverse: List[Dict[str, Any]],
) -> None:
    syn = next((packet for packet in forward if packet["flags"] & dpkt.tcp.TH_SYN), None)
    synack = next(
        (packet for packet in reverse if packet["flags"] & dpkt.tcp.TH_SYN and packet["flags"] & dpkt.tcp.TH_ACK),
        None,
    )
    ack = next(
        (packet for packet in forward if packet["flags"] & dpkt.tcp.TH_ACK and not packet["flags"] & dpkt.tcp.TH_SYN),
        None,
    )
    if syn is not None and synack is not None:
        values["synack"] = synack["timestamp"] - syn["timestamp"]
        values["tcprtt"] = values["synack"]
    if synack is not None and ack is not None:
        values["ackdat"] = ack["timestamp"] - synack["timestamp"]

    values.update(_directional_timing("s", forward))
    values.update(_directional_timing("d", reverse))


def _directional_timing(prefix: str, packets: List[Dict[str, Any]]) -> Dict[str, float]:
    timestamps = [packet["timestamp"] for packet in packets]
    if len(timestamps) < 2:
        return {}
    intervals = [current - previous for previous, current in zip(timestamps, timestamps[1:])]
    mean = sum(intervals) / len(intervals)
    variance = sum((value - mean) ** 2 for value in intervals) / len(intervals)
    return {f"{prefix}inpkt": mean, f"{prefix}jit": variance ** 0.5}


def _ip_text(value: bytes) -> str:
    return ".".join(str(part) for part in value)