"""Window/state management for detector-specific time windows."""

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional

from backend.ingestor import NormalizedEvent


@dataclass
class WindowConfig:
    """Detector-specific window configuration."""
    detector_name: str
    window_type: str  # "tumbling" or "rolling"
    window_size_seconds: int
    group_by: List[str]
    max_events: Optional[int] = None  # For rolling windows (e.g., last 5)


@dataclass
class WindowState:
    """Active time window for a detector."""
    window_id: str
    config: WindowConfig
    group_key: str
    start_time: datetime
    events: List[NormalizedEvent] = field(default_factory=list)


class WindowManager:
    """Manages time windows per detector requirements."""

    def __init__(self) -> None:
        self._configs: Dict[str, WindowConfig] = {}
        self._windows: Dict[str, WindowState] = {}

    def register_config(self, config: WindowConfig) -> None:
        """Register window config for a detector."""
        self._configs[config.detector_name] = config

    def get_config(self, detector_name: str) -> Optional[WindowConfig]:
        """Get window config for detector."""
        return self._configs.get(detector_name)

    def add_event(self, event: NormalizedEvent, detector_name: str) -> List[WindowState]:
        """
        Add event to appropriate window(s). Returns completed windows.
        """
        config = self._configs.get(detector_name)
        if not config:
            return []

        group_key = self._make_group_key(event, config.group_by)
        window_key = f"{detector_name}:{group_key}"

        # Get or create window
        window = self._windows.get(window_key)
        now = datetime.fromtimestamp(event.ts)
        completed: List[WindowState] = []

        if not window or self._is_window_expired(window, now, config):
            # Complete old window if exists
            if window and window.events:
                completed.append(window)

            # Create new window
            window = WindowState(
                window_id=f"win-{uuid.uuid4().hex[:8]}",
                config=config,
                group_key=group_key,
                start_time=now,
            )
            self._windows[window_key] = window

        window.events.append(event)

        # Check rolling window max events
        if config.window_type == "rolling" and config.max_events:
            if len(window.events) > config.max_events:
                window.events = window.events[-config.max_events:]

        return completed

    def flush_all(self) -> List[WindowState]:
        """Flush all active windows (for testing/end)."""
        completed = [w for w in self._windows.values() if w.events]
        self._windows.clear()
        return completed

    def _make_group_key(self, event: NormalizedEvent, group_by: List[str]) -> str:
        """Create group key from event fields."""
        parts = []
        for field_name in group_by:
            if field_name == "src_ip":
                parts.append(event.src_ip)
            elif field_name == "dst_ip":
                parts.append(event.dst_ip)
            elif field_name == "proto":
                parts.append(event.proto)
            elif field_name == "dst_port":
                parts.append(str(event.dst_port))
            elif field_name == "src_port":
                parts.append(str(event.src_port))
            else:
                parts.append("unknown")
        return "|".join(parts)

    def _is_window_expired(self, window: WindowState, now: datetime, config: WindowConfig) -> bool:
        """Check if window has expired."""
        elapsed = (now - window.start_time).total_seconds()
        return elapsed >= config.window_size_seconds
