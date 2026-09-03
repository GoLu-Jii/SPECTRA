"""Runtime metrics tracking for the P3 detection pipeline.

Tracks event counts, alert counts, processing throughput, inference
latency, end-to-end latency, queue depth, and dropped events. Powered by
``/stats`` and surfaced to the runner.
"""

import time
from typing import Any, Dict, List


class Metrics:
    """Tracks counts, latencies, and throughput for the pipeline."""

    def __init__(self) -> None:
        self._start = time.monotonic()
        self.events_received: int = 0
        self.events_processed: int = 0
        self.alerts_generated: int = 0
        self.dropped_events: int = 0
        self.queue_depth: int = 0
        self._inference_latencies: List[float] = []
        self._e2e_latencies: List[float] = []

    def record_inference_latency(self, seconds: float) -> None:
        """Record the time spent running detectors on one event."""
        self._inference_latencies.append(seconds)

    def record_e2e_latency(self, seconds: float) -> None:
        """Record the time from event receipt to alert generation."""
        self._e2e_latencies.append(seconds)

    def set_queue_depth(self, depth: int) -> None:
        """Record the current ingestion queue depth."""
        self.queue_depth = depth

    def snapshot(self) -> Dict[str, Any]:
        """Return a JSON-serializable metrics snapshot for /stats."""
        elapsed = max(time.monotonic() - self._start, 1e-9)

        def _latency_stats(lats: List[float]) -> Dict[str, Any]:
            if not lats:
                return {"count": 0}
            return {
                "count": len(lats),
                "avg_seconds": round(sum(lats) / len(lats), 6),
                "max_seconds": round(max(lats), 6),
                "latest_seconds": round(lats[-1], 6),
            }

        return {
            "events_received": self.events_received,
            "events_processed": self.events_processed,
            "alerts_generated": self.alerts_generated,
            "dropped_events": self.dropped_events,
            "queue_depth": self.queue_depth,
            "throughput_events_per_sec": round(self.events_processed / elapsed, 4),
            "uptime_seconds": round(elapsed, 3),
            "inference_latency": _latency_stats(self._inference_latencies),
            "end_to_end_latency": _latency_stats(self._e2e_latencies),
        }
