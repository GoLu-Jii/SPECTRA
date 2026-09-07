import asyncio
import time
from unittest.mock import Mock

import pytest

from backend.metrics import Metrics
from backend.orchestrator import Orchestrator
from backend.runner import Runner
from backend.store import AlertStore
from backend.windowing import WindowConfig
from backend.ingestor import NormalizedEvent
from ml_engine.mock.detector import MockDetector


class RaisingDetector(MockDetector):
    """Test detector used to characterize worker failure behavior."""

    def predict(self, features, context):
        raise RuntimeError("detector failure")


def make_event(timestamp: float, uid: str) -> NormalizedEvent:
    return NormalizedEvent(
        ts=timestamp,
        uid=uid,
        src_ip="192.0.2.10",
        src_port=40000,
        dst_ip="198.51.100.20",
        dst_port=443,
        proto="tcp",
        log_type="conn",
        duration=0.1,
        orig_bytes=100,
        resp_bytes=50,
        orig_pkts=3,
        resp_pkts=2,
        history="S",
    )


async def wait_for(condition, timeout=2.0):
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() >= deadline:
            raise AssertionError("condition was not reached before timeout")
        await asyncio.sleep(0.001)


def build_runner(window_size=60, detector=None):
    orchestrator = Orchestrator()
    detector = detector or MockDetector()
    orchestrator.register_detector(
        detector,
        WindowConfig("mock", "tumbling", window_size, ["dst_ip"]),
    )
    metrics = Metrics()
    store = AlertStore()
    runner = Runner(orchestrator, store=store, metrics=metrics)
    return runner, store, metrics, detector


def test_incremental_slow_producer_drains_and_records_latency():
    async def run_stream():
        runner, store, metrics, _ = build_runner(window_size=1)
        arrivals = {}

        await runner.start()
        try:
            for index in range(4):
                event = make_event(float(index), f"STREAM-{index}")
                arrivals[event.uid] = time.monotonic()
                await runner.feed(event)
                await asyncio.sleep(0.01)

            await wait_for(lambda: metrics.events_processed == 4)
            assert metrics.events_received == 4
            assert metrics.dropped_events == 0
            assert runner._queue.qsize() == 0
            assert metrics.queue_depth == 0
            assert len(store.get_all()) == 3
            snapshot = metrics.snapshot()
            assert snapshot["events_processed"] == snapshot["events_received"] == 4
            assert snapshot["inference_latency"]["count"] == 4
            assert snapshot["end_to_end_latency"]["count"] == 3
            assert snapshot["throughput_events_per_sec"] > 0
            expected_throughput = snapshot["events_processed"] / snapshot["uptime_seconds"]
            assert abs(snapshot["throughput_events_per_sec"] - expected_throughput) < 2.0
            assert all(time.monotonic() - arrival < 2.0 for arrival in arrivals.values())
        finally:
            await runner.stop()

    asyncio.run(run_stream())


def test_window_boundary_generates_alert_before_stream_ends():
    async def run_stream():
        runner, store, metrics, detector = build_runner(window_size=1)
        detector.predict = Mock(wraps=detector.predict)
        first = make_event(100.0, "WINDOW-1")
        boundary = make_event(101.0, "WINDOW-2")

        await runner.start()
        try:
            await runner.feed(first)
            await wait_for(lambda: metrics.events_processed == 1)
            assert store.get_all() == []

            await runner.feed(boundary)
            await wait_for(lambda: len(store.get_all()) == 1)

            assert metrics.events_received == 2
            assert metrics.events_processed == 2
            assert detector.predict.call_count == 1
            assert store.get_all()[0].threat_classification.threat_class == "MOCK_THREAT"
        finally:
            await runner.stop()

    asyncio.run(run_stream())


def test_runner_shutdown_terminates_worker_cleanly():
    async def run_stream():
        runner, store, metrics, _ = build_runner(window_size=1)

        await runner.start()
        await runner.feed(make_event(1.0, "SHUTDOWN-1"))
        await runner.feed(make_event(2.0, "SHUTDOWN-2"))
        await wait_for(lambda: metrics.events_processed == 2)
        task = runner._task
        await runner.stop()

        assert task.done()
        assert runner._task is None
        assert metrics.events_received == metrics.events_processed == 2
        assert len(store.get_all()) == 1

    asyncio.run(run_stream())


def test_detector_failure_isolation_is_not_supported():
    async def run_stream():
        runner, _, metrics, _ = build_runner(window_size=1, detector=RaisingDetector())

        await runner.start()
        await runner.feed(make_event(1.0, "FAILURE-1"))
        await runner.feed(make_event(2.0, "FAILURE-2"))
        await wait_for(lambda: runner._task.done())

        assert isinstance(runner._task.exception(), RuntimeError)
        assert metrics.events_received == 2
        assert metrics.events_processed == 1
        # The current Runner has no per-detector exception boundary. This test
        # documents the hardening gap without changing production behavior.
        with pytest.raises(RuntimeError, match="detector failure"):
            await runner.stop()

    asyncio.run(run_stream())
