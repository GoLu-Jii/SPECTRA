"""Event-driven streaming/replay runner for the P3 pipeline.

Consumes ``NormalizedEvent`` objects (from passive ingestion), feeds each
through the stateful ``Orchestrator`` (which holds detector windows), and
pushes generated alerts to the ``AlertStore`` and live subscribers.

Events are processed one at a time via an in-process ``asyncio.Queue`` so
the pipeline stays event-driven (not a batch ML redesign). The same runner
supports live ``feed()`` ingestion and ``replay_directory()`` for demo data.
"""

import asyncio
import time
from typing import List, Optional

from backend.ingestor import NormalizedEvent, Ingestor
from backend.orchestrator import Orchestrator
from backend.metrics import Metrics
from backend.store import AlertStore


class Runner:
    """Drives NormalizedEvents through the detection pipeline."""

    def __init__(
        self,
        orchestrator: Orchestrator,
        store: Optional[AlertStore] = None,
        metrics: Optional[Metrics] = None,
        max_queue: int = 0,
    ) -> None:
        self.orchestrator = orchestrator
        self.store = store if store is not None else AlertStore()
        self.metrics = metrics if metrics is not None else Metrics()
        self._max_queue = max_queue
        # The queue is created lazily in start() so it binds to the event
        # loop that actually runs the runner (avoids cross-loop bindings).
        self._queue: Optional[asyncio.Queue] = None
        self._subscribers: "set[asyncio.Queue]" = set()
        self._task: Optional[asyncio.Task] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def start(self) -> None:
        """Start the background worker task."""
        if self._task is None:
            self._queue = asyncio.Queue(maxsize=self._max_queue)
            self._task = asyncio.create_task(self._worker())

    async def stop(self) -> None:
        """Cancel the background worker task."""
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------
    async def feed(self, event: NormalizedEvent) -> None:
        """Enqueue a single event for live processing (non-blocking)."""
        self.metrics.events_received += 1
        if self._queue.full():
            self.metrics.dropped_events += 1
            return
        await self._queue.put(event)

    async def replay_events(self, events: List[NormalizedEvent]) -> int:
        """Replay a list of events; return the number of alerts generated."""
        before = self.metrics.alerts_generated
        for ev in events:
            self.metrics.events_received += 1
            await self._queue.put(ev)

        # Wait for the worker to drain the queue, then flush any windows
        # that never received a triggering "next" event.
        await self._queue.join()
        flushed = self.orchestrator.flush_windows()
        await self._emit_alerts(flushed)

        return self.metrics.alerts_generated - before

    async def replay_directory(self, directory: str) -> int:
        """Replay all Zeek log files in a directory; return alert count."""
        ingestor = Ingestor()
        events = ingestor.ingest_directory(directory)
        return await self.replay_events(events)

    # ------------------------------------------------------------------
    # Live delivery
    # ------------------------------------------------------------------
    async def subscribe(self) -> "asyncio.Queue":
        """Return a subscriber queue that receives serialized alerts."""
        q: asyncio.Queue = asyncio.Queue()
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: "asyncio.Queue") -> None:
        """Remove a subscriber queue."""
        self._subscribers.discard(q)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    async def _worker(self) -> None:
        """Consume events from the queue and run them through the pipeline."""
        while True:
            event = await self._queue.get()
            try:
                self.metrics.set_queue_depth(self._queue.qsize())
                received_at = time.monotonic()

                t0 = time.monotonic()
                alerts = self.orchestrator.process_events([event])
                self.metrics.record_inference_latency(time.monotonic() - t0)

                self.metrics.events_processed += 1
                await self._emit_alerts(alerts, received_at=received_at)
            finally:
                self._queue.task_done()

    async def _emit_alerts(
        self,
        alerts: List,
        received_at: Optional[float] = None,
    ) -> None:
        """Store, count, and broadcast generated alerts."""
        for alert in alerts:
            self.store.add(alert)
            self.metrics.alerts_generated += 1
            if received_at is not None:
                self.metrics.record_e2e_latency(time.monotonic() - received_at)
            await self._broadcast(alert)

    async def _broadcast(self, alert) -> None:
        """Push a serialized alert to every live subscriber."""
        payload = alert.model_dump_json()
        dead: List["asyncio.Queue"] = []
        for q in list(self._subscribers):
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            self.unsubscribe(q)
