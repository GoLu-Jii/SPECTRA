"""Zeek log ingestion and normalization."""

import os
import glob
from dataclasses import dataclass, field
from typing import Dict, Any, List, Tuple, Optional


@dataclass
class NormalizedEvent:
    """Internal ingestion representation. NOT an API schema."""

    # === Common (all log types) ===
    ts: float                     # Epoch timestamp
    uid: str                      # Zeek correlation key
    src_ip: str                   # id.orig_h
    src_port: int                 # id.orig_p
    dst_ip: str                   # id.resp_h
    dst_port: int                 # id.resp_p
    proto: str                    # TCP / UDP / ICMP
    log_type: str                 # conn | dns | ssl | http

    # === conn.log ===
    duration: Optional[float] = None
    orig_bytes: Optional[int] = None
    resp_bytes: Optional[int] = None
    conn_state: Optional[str] = None
    service: Optional[str] = None
    history: Optional[str] = None
    orig_pkts: Optional[int] = None
    resp_pkts: Optional[int] = None

    # === dns.log ===
    query: Optional[str] = None
    rcode_name: Optional[str] = None
    qtype_name: Optional[str] = None
    answers: Optional[list] = None

    # === ssl.log ===
    ssl_version: Optional[str] = None
    cipher: Optional[str] = None
    ja4: Optional[str] = None
    ja3: Optional[str] = None
    server_name: Optional[str] = None

    # === http.log ===
    method: Optional[str] = None
    uri: Optional[str] = None
    status_code: Optional[int] = None
    request_body_len: Optional[int] = None
    response_body_len: Optional[int] = None

    # === Fallback: every original raw field preserved ===
    raw: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Zeek TSV type conversions
# ---------------------------------------------------------------------------

_ZEEK_TYPE_CONVERTERS = {
    "time": lambda v: float(v),
    "interval": lambda v: float(v),
    "count": lambda v: int(v),
    "port": lambda v: int(v),
    "addr": lambda v: str(v),
    "string": lambda v: str(v),
    "enum": lambda v: str(v),
    "bool": lambda v: v == "T",
    "set[string]": lambda v: v.split(",") if v and v != "-" else [],
    "vector[string]": lambda v: v.split(",") if v and v != "-" else [],
    "vector[interval]": lambda v: [float(x) for x in v.split(",")] if v and v != "-" else [],
}


class LogReader:
    """Parses a single Zeek log file into typed dictionaries."""

    def read(self, filepath: str) -> Dict[str, Any]:
        """
        Parse Zeek TSV log file.

        Returns:
            {
                "log_type": "conn",
                "fields": ["ts", "uid", ...],
                "events": [{"ts": 1788359400.12, "uid": "C101", ...}, ...]
            }
        """
        log_type = self._log_type_from_path(filepath)

        with open(filepath, "r", encoding="utf-8") as f:
            lines = [line.rstrip("\n") for line in f]

        field_names, field_types = self._parse_header(lines)
        data_lines = [l for l in lines if l and not l.startswith("#")]

        events = []
        for line in data_lines:
            raw_values = line.split("\t")
            event = {}
            for i, fname in enumerate(field_names):
                raw_val = raw_values[i] if i < len(raw_values) else "-"
                zeek_type = field_types[i] if i < len(field_types) else "string"
                event[fname] = self._parse_field_value(raw_val, zeek_type)
            events.append(event)

        return {
            "log_type": log_type,
            "fields": field_names,
            "events": events,
        }

    def _log_type_from_path(self, filepath: str) -> str:
        """Extract log type from filename (e.g., conn.log -> conn)."""
        basename = os.path.basename(filepath)
        name = basename.split(".")[0]
        return name

    def _parse_header(self, lines: List[str]) -> Tuple[List[str], List[str]]:
        """Extract field names and types from Zeek #fields/#types headers."""
        field_names: List[str] = []
        field_types: List[str] = []

        for line in lines:
            if line.startswith("#fields\t"):
                field_names = line.split("\t")[1:]
            elif line.startswith("#types\t"):
                field_types = line.split("\t")[1:]

        return field_names, field_types

    def _parse_field_value(self, value: str, zeek_type: str) -> Any:
        """Convert string value to Python type based on Zeek type declaration."""
        if value == "-" or value == "(empty)":
            return None

        converter = _ZEEK_TYPE_CONVERTERS.get(zeek_type)
        if converter:
            try:
                return converter(value)
            except (ValueError, TypeError):
                return value
        return value


# ---------------------------------------------------------------------------
# Field mapping: Zeek raw names -> NormalizedEvent field names
# ---------------------------------------------------------------------------

_FIELD_MAP: Dict[str, Dict[str, Any]] = {
    # Zeek field name -> {"dest": NormalizedEvent attr, "type": Python type}
    "ts":               {"dest": "ts",               "type": float},
    "uid":              {"dest": "uid",              "type": str},
    "id.orig_h":        {"dest": "src_ip",           "type": str},
    "id.orig_p":        {"dest": "src_port",         "type": int},
    "id.resp_h":        {"dest": "dst_ip",           "type": str},
    "id.resp_p":        {"dest": "dst_port",         "type": int},
    "proto":            {"dest": "proto",            "type": str},
    # conn.log
    "duration":         {"dest": "duration",         "type": float},
    "orig_bytes":       {"dest": "orig_bytes",       "type": int},
    "resp_bytes":       {"dest": "resp_bytes",       "type": int},
    "conn_state":       {"dest": "conn_state",       "type": str},
    "service":          {"dest": "service",          "type": str},
    "history":          {"dest": "history",          "type": str},
    "orig_pkts":        {"dest": "orig_pkts",        "type": int},
    "resp_pkts":        {"dest": "resp_pkts",        "type": int},
    # dns.log
    "query":            {"dest": "query",            "type": str},
    "rcode_name":       {"dest": "rcode_name",       "type": str},
    "qtype_name":       {"dest": "qtype_name",       "type": str},
    "answers":          {"dest": "answers",          "type": list},
    # ssl.log
    "version":          {"dest": "ssl_version",      "type": str},
    "cipher":           {"dest": "cipher",           "type": str},
    "ja4":              {"dest": "ja4",              "type": str},
    "ja3":              {"dest": "ja3",              "type": str},
    "server_name":      {"dest": "server_name",      "type": str},
    # http.log
    "method":           {"dest": "method",           "type": str},
    "uri":              {"dest": "uri",              "type": str},
    "status_code":      {"dest": "status_code",      "type": int},
    "request_body_len": {"dest": "request_body_len", "type": int},
    "response_body_len":{"dest": "response_body_len","type": int},
}


class Normalizer:
    """Converts raw parsed events to NormalizedEvent. Pure function, no state."""

    def normalize_raw(self, raw_events: List[Dict], log_type: str) -> List[NormalizedEvent]:
        """Normalize a batch of raw events from a single log type."""
        return [self.normalize_event(ev, log_type) for ev in raw_events]

    def normalize_event(self, raw: Dict, log_type: str) -> NormalizedEvent:
        """Normalize a single raw Zeek event into NormalizedEvent."""
        fields: Dict[str, Any] = {}

        for zeek_name, mapping in _FIELD_MAP.items():
            if zeek_name in raw:
                val = raw[zeek_name]
                if val is not None:
                    try:
                        fields[mapping["dest"]] = mapping["type"](val)
                    except (ValueError, TypeError):
                        fields[mapping["dest"]] = val
                else:
                    fields[mapping["dest"]] = None

        fields["log_type"] = log_type
        fields["raw"] = dict(raw)

        # ssl.log and http.log don't have proto field (always TCP)
        if "proto" not in fields:
            fields["proto"] = "tcp"

        return NormalizedEvent(**fields)


class Ingestor:
    """
    Top-level file ingestion facade.
    Combines LogReader + Normalizer. Stateless.
    """

    def __init__(self) -> None:
        self._reader = LogReader()
        self._normalizer = Normalizer()

    def ingest_file(self, filepath: str) -> List[NormalizedEvent]:
        """Read one Zeek log file, return normalized events."""
        parsed = self._reader.read(filepath)
        return self._normalizer.normalize_raw(parsed["events"], parsed["log_type"])

    def ingest_directory(self, directory: str) -> List[NormalizedEvent]:
        """Read all Zeek log files from a directory, return normalized events."""
        pattern = os.path.join(directory, "*.log")
        log_files = sorted(glob.glob(pattern))

        events: List[NormalizedEvent] = []
        for log_file in log_files:
            events.extend(self.ingest_file(log_file))

        return events
