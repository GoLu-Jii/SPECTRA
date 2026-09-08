"""Feature preparation for the UNSW-NB15 data exfiltration model."""

from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass
from typing import Any, Deque, Dict, Iterable, Optional

import pandas as pd

from backend.ingestor import NormalizedEvent


PACKET_FEATURES = (
    "sttl", "dttl", "sloss", "dloss", "sinpkt", "dinpkt", "sjit", "djit",
    "swin", "dwin", "stcpb", "dtcpb", "tcprtt", "synack", "ackdat",
)


@dataclass(frozen=True)
class ExfiltrationFeatureResult:
    """Prepared model input and the fields used to explain it."""

    payload: Dict[str, Any]
    feature_names: tuple[str, ...]


class ExfiltrationFeatureError(ValueError):
    """Raised when a flow cannot be represented without fabricated values."""


class ExfiltrationFeatureAdapter:
    """Build one complete model row from a normalized flow and packet metadata."""

    def __init__(self, expected_features: Iterable[str], history_size: int = 100) -> None:
        self.expected_features = tuple(expected_features)
        self._history: Deque[Dict[str, Any]] = deque(maxlen=history_size)

    def prepare(self, event: NormalizedEvent) -> ExfiltrationFeatureResult:
        packet = self._packet_metadata(event)
        duration = self._number(event.duration, "duration")
        if duration <= 0:
            raise ExfiltrationFeatureError("duration must be positive")

        source_packets = self._number(event.orig_pkts, "orig_pkts")
        destination_packets = self._number(event.resp_pkts, "resp_pkts")
        if source_packets <= 0 or destination_packets <= 0:
            raise ExfiltrationFeatureError(
                "orig_pkts and resp_pkts must be positive for mean features"
            )
        source_bytes = self._number(event.orig_bytes, "orig_bytes")
        destination_bytes = self._number(event.resp_bytes, "resp_bytes")
        if not event.service or not event.conn_state:
            raise ExfiltrationFeatureError(
                "service and conn_state are required categorical features"
            )
        service = event.service
        state = event.conn_state
        proto = event.proto

        row: Dict[str, Any] = {
            "dur": duration,
            "spkts": source_packets,
            "dpkts": destination_packets,
            "sbytes": source_bytes,
            "dbytes": destination_bytes,
            "rate": self._number(event.raw.get("rate"), "rate"),
            "sload": source_bytes * 8 / duration,
            "dload": destination_bytes * 8 / duration,
            "smean": source_bytes / source_packets if source_packets else 0.0,
            "dmean": destination_bytes / destination_packets if destination_packets else 0.0,
            "trans_depth": self._number(
                event.raw.get("trans_depth"), "trans_depth"
            ),
            "response_body_len": self._number(
                event.response_body_len, "response_body_len"
            ),
            "is_ftp_login": self._number(
                event.raw.get("is_ftp_login"), "is_ftp_login"
            ),
            "ct_ftp_cmd": self._number(event.raw.get("ct_ftp_cmd"), "ct_ftp_cmd"),
            "ct_flw_http_mthd": self._number(
                event.raw.get("ct_flw_http_mthd"), "ct_flw_http_mthd"
            ),
            "proto": proto,
            "service": service,
            "state": state,
        }
        row.update({name: self._number(packet[name], name) for name in PACKET_FEATURES})
        row.update(self._historical_features(event, row))

        missing = [name for name in self._required_base_features() if name not in row]
        if missing:
            raise ExfiltrationFeatureError(f"missing semantic features: {missing}")

        # Verify the wrapper's actual preprocessing contract before inference.
        aligned = self._align(row)
        if tuple(aligned.columns) != self.expected_features:
            raise ExfiltrationFeatureError("aligned feature order does not match artifact")
        if len(aligned.columns) != 187:
            raise ExfiltrationFeatureError("artifact feature count is not 187")

        self._history.append(self._history_record(event, row))
        return ExfiltrationFeatureResult(payload=row, feature_names=tuple(aligned.columns))

    def _required_base_features(self) -> tuple[str, ...]:
        return tuple(name for name in self.expected_features if not name.startswith(("proto_", "service_", "state_")))

    def _align(self, row: Dict[str, Any]) -> pd.DataFrame:
        frame = pd.get_dummies(pd.DataFrame([row]))
        return frame.reindex(columns=self.expected_features, fill_value=0)

    @staticmethod
    def _packet_metadata(event: NormalizedEvent) -> Dict[str, Any]:
        metadata = event.raw.get("exfiltration_packet")
        if not isinstance(metadata, dict):
            raise ExfiltrationFeatureError(
                "packet metadata is required under raw['exfiltration_packet']"
            )
        missing = [name for name in PACKET_FEATURES if name not in metadata]
        if missing:
            raise ExfiltrationFeatureError(f"missing packet features: {missing}")
        return metadata

    @staticmethod
    def _number(value: Any, name: str) -> float:
        if value is None:
            raise ExfiltrationFeatureError(f"missing numeric feature: {name}")
        try:
            number = float(value)
        except (TypeError, ValueError) as exc:
            raise ExfiltrationFeatureError(f"invalid numeric feature: {name}") from exc
        if not math.isfinite(number):
            raise ExfiltrationFeatureError(f"non-finite numeric feature: {name}")
        return number

    @classmethod
    def _optional_number(cls, value: Any, name: str) -> float:
        if value is None:
            return 0.0
        return cls._number(value, name)

    def _historical_features(
        self, event: NormalizedEvent, row: Dict[str, Any]
    ) -> Dict[str, int]:
        history = list(self._history)
        current = self._history_record(event, row)
        same = lambda key: sum(item[key] == current[key] for item in history)
        return {
            "ct_srv_src": same("service_src"),
            "ct_state_ttl": same("state_ttl"),
            "ct_dst_ltm": same("dst_ip"),
            "ct_src_dport_ltm": same("src_dport"),
            "ct_dst_sport_ltm": same("dst_sport"),
            "ct_dst_src_ltm": same("dst_src"),
            "ct_src_ltm": same("src_ip"),
            "ct_srv_dst": same("service_dst"),
            "is_sm_ips_ports": int(event.src_ip == event.dst_ip and event.src_port == event.dst_port),
        }

    @staticmethod
    def _history_record(event: NormalizedEvent, row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "service_src": (row["service"], event.src_ip),
            "state_ttl": (row["state"], row["sttl"]),
            "dst_ip": event.dst_ip,
            "src_dport": (event.src_ip, event.dst_port),
            "dst_sport": (event.dst_ip, event.src_port),
            "dst_src": (event.dst_ip, event.src_ip),
            "src_ip": event.src_ip,
            "service_dst": (row["service"], event.dst_ip),
        }