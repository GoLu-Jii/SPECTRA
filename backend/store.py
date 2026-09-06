"""In-process alert store for the prototype.

Holds standardized ``Alert`` objects in memory with bounded capacity.
No database is introduced (prototype scope).
"""

import threading
from typing import List, Optional

from backend.schemas import Alert


class AlertStore:
    """Bounded, thread-safe in-process store for generated alerts."""

    def __init__(self, max_size: int = 10000) -> None:
        self._max_size = max_size
        self._alerts: List[Alert] = []
        self._index = {}  # alert_id -> Alert
        self._lock = threading.Lock()

    def add(self, alert: Alert) -> None:
        """Store an alert, trimming the oldest if capacity is exceeded."""
        with self._lock:
            self._index[alert.alert_id] = alert
            self._alerts.append(alert)
            if len(self._alerts) > self._max_size:
                removed = self._alerts.pop(0)
                self._index.pop(removed.alert_id, None)

    def get_all(self) -> List[Alert]:
        """Return all stored alerts (newest appended last)."""
        with self._lock:
            return list(self._alerts)

    def get(self, alert_id: str) -> Optional[Alert]:
        """Return a single alert by id, or None if not found."""
        with self._lock:
            return self._index.get(alert_id)

    def __len__(self) -> int:
        with self._lock:
            return len(self._alerts)
