"""Event-driven streaming/replay runner for the P3 pipeline.

Consumes ``NormalizedEvent`` objects (from passive ingestion), feeds each
through the stateful ``Orchestrator`` (which holds detector windows), and
pushes generated alerts to the ``AlertStore`` and live subscribers.

Events are processed one at a time via an in-process ``asyncio.Queue`` so
the pipeline stays event-driven (not a batch ML redesign). The same runner
supports live ``feed()`` ingestion and ``replay_directory()`` for demo data.
"""

import asyncio
import logging
import time
from typing import List, Optional

from backend.ingestor import NormalizedEvent, Ingestor
from backend.orchestrator import Orchestrator
from backend.metrics import Metrics
from backend.store import AlertStore


logger = logging.getLogger(__name__)


class Runner:
    """Drives NormalizedEvents through the detection pipeline."""

    def __init__(
        self,
        orchestrator: Orchestrator,
        store: Optional[AlertStore] = None,
        metrics: Optional[Metrics] = None,
        max_queue: int = 1000,
        shutdown_timeout: float = 5.0,
        subscriber_queue_size: int = 100,
    ) -> None:
        if max_queue <= 0:
            raise ValueError("max_queue must be greater than zero")
        if shutdown_timeout <= 0:
            raise ValueError("shutdown_timeout must be greater than zero")
        if subscriber_queue_size <= 0:
            raise ValueError("subscriber_queue_size must be greater than zero")
        self.orchestrator = orchestrator
        self.store = store if store is not None else AlertStore()
        self.metrics = metrics if metrics is not None else Metrics()
        self._max_queue = max_queue
        self._shutdown_timeout = shutdown_timeout
        self._subscriber_queue_size = subscriber_queue_size
        # The queue is created lazily in start() so it binds to the event
        # loop that actually runs the runner (avoids cross-loop bindings).
        self._queue: Optional[asyncio.Queue] = None
        self._subscribers: "set[asyncio.Queue]" = set()
        self._task: Optional[asyncio.Task] = None
        self._initialized = False
        self._accepting = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def start(self) -> None:
        """Start the background worker task."""
        if self._task is None:
            self._queue = asyncio.Queue(maxsize=self._max_queue)
            self._task = asyncio.create_task(self._worker())
            self._initialized = True
            self._accepting = True

    async def stop(self) -> None:
        """Cancel the background worker task."""
        self._accepting = False
        task = self._task
        queue = self._queue
        if task is None:
            return

        if queue is not None:
            try:
                await asyncio.wait_for(queue.join(), timeout=self._shutdown_timeout)
            except asyncio.TimeoutError:
                abandoned = 0
                while True:
                    try:
                        queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break
                    queue.task_done()
                    abandoned += 1
                self.metrics.abandoned_events += abandoned
                self.metrics.set_queue_depth(0)

        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        self._task = None

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------
    async def feed(
        self,
        event: NormalizedEvent,
        *,
        wait_for_capacity: bool = False,
    ) -> None:
        """Enqueue one event, optionally waiting for replay capacity."""
        self.metrics.events_received += 1
        if not self._accepting or self._queue is None or self._queue.full():
            if wait_for_capacity and self._accepting and self._queue is not None:
                await self._queue.put(event)
                return
            self.metrics.dropped_events += 1
            return
        self._queue.put_nowait(event)

    async def replay_events(self, events: List[NormalizedEvent]) -> int:
        """Replay a list of events; return the number of alerts generated."""
        before = self.metrics.alerts_generated
        for ev in events:
            await self.feed(ev, wait_for_capacity=True)

        # Wait for the worker to drain the queue, then flush any windows
        # that never received a triggering "next" event.
        await self._queue.join()
        try:
            flushed = self.orchestrator.flush_windows()
        except Exception:
            self.metrics.detector_failures += 1
            logger.exception("Final detector window flush failed; continuing replay")
            flushed = []
        await self._emit_alerts(flushed)

        return self.metrics.alerts_generated - before

    async def replay_directory(self, directory: str) -> int:
        """Replay all Zeek log files in a directory; return alert count."""
        ingestor = Ingestor(metrics=self.metrics)
        events = ingestor.ingest_directory(directory)
        return await self.replay_events(events)

    # ------------------------------------------------------------------
    # Live delivery
    # ------------------------------------------------------------------
    async def subscribe(self) -> "asyncio.Queue":
        """Return a subscriber queue that receives serialized alerts."""
        q: asyncio.Queue = asyncio.Queue(maxsize=self._subscriber_queue_size)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: "asyncio.Queue") -> None:
        """Remove a subscriber queue."""
        self._subscribers.discard(q)

    def lifecycle_state(self) -> str:
        """Return the current worker lifecycle state."""
        if not self._initialized:
            return "not_initialized"
        if self._task is None:
            return "stopped"
        if self._task.done():
            if self._task.cancelled():
                return "stopped"
            if self._task.exception() is not None:
                return "failed"
            return "stopped"
        return "running"

    def is_ready(self) -> bool:
        """Return whether the worker is alive and accepting events."""
        return self._accepting and self.lifecycle_state() == "running"

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
                try:
                    alerts = self.orchestrator.process_events([event])
                except Exception:
                    self.metrics.detector_failures += 1
                    logger.exception(
                        "Event processing failed; continuing stream",
                        extra={"event_uid": event.uid, "log_type": event.log_type},
                    )
                    alerts = []
                finally:
                    self.metrics.record_inference_latency(time.monotonic() - t0)

                self.metrics.events_processed += 1
                await self._emit_alerts(alerts, received_at=received_at)
            finally:
                self._queue.task_done()
                await asyncio.sleep(0)

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
                logger.warning("Removing slow WebSocket subscriber with full queue")
                dead.append(q)
        for q in dead:
            self.unsubscribe(q)
