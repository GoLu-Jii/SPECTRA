import asyncio
import json
from pathlib import Path

from backend.evaluation import evaluate_zeek_directory
from backend.metrics import Metrics
from backend.orchestrator import Orchestrator
from backend.runner import Runner
from backend.store import AlertStore
from backend.test_streaming_runtime import make_event, wait_for
from backend.windowing import WindowConfig
from ml_engine.mock.detector import MockDetector


ZEEK_FIXTURE = Path("data_and_demo/zeek_logs")


class FailOnceDetector(MockDetector):
    def __init__(self):
        self.failed = False

    def predict(self, features, context):
        if not self.failed:
            self.failed = True
            raise RuntimeError("controlled evaluation failure")
        return super().predict(features, context)


def test_zeek_evaluation_summary_is_complete_and_json_serializable():
    first = evaluate_zeek_directory(ZEEK_FIXTURE)
    second = evaluate_zeek_directory(ZEEK_FIXTURE)

    assert first["source"]["event_count"] == 15
    assert first["runtime"]["events_received"] == 15
    assert first["runtime"]["events_processed"] == 15
    assert first["runtime"]["dropped_events"] == 0
    assert first["runtime"]["queue_depth"] == 0
    assert first["runtime"]["worker_alive_after_drain"] is True
    assert first["runtime"]["detector_failures"] == 0
    assert first["runtime"]["replay_duration_seconds"] > 0
    assert first["performance"]["events_per_second"] > 0

    alerts = first["alerts"]
    assert alerts["total"] > 0
    assert alerts["by_threat_class"]
    assert alerts["by_severity"]
    assert alerts["confidence"]["min"] is not None
    assert 0.0 <= alerts["confidence"]["min"] <= 1.0
    assert 0.0 <= alerts["confidence"]["max"] <= 1.0
    assert 0.0 <= alerts["confidence"]["average"] <= 1.0
    assert first["ground_truth"] == {
        "available": False,
        "accuracy_metrics": None,
    }
    json.dumps(first)

    assert first["source"]["event_count"] == second["source"]["event_count"]
    assert first["runtime"]["events_received"] == second["runtime"]["events_received"]
    assert first["runtime"]["events_processed"] == second["runtime"]["events_processed"]
    assert first["alerts"]["total"] == second["alerts"]["total"]
    assert first["alerts"]["by_threat_class"] == second["alerts"]["by_threat_class"]
    assert first["alerts"]["by_severity"] == second["alerts"]["by_severity"]


def test_detector_failure_is_counted_and_worker_continues():
    async def run_stream():
        detector = FailOnceDetector()
        orchestrator = Orchestrator()
        orchestrator.register_detector(
            detector,
            WindowConfig("mock", "tumbling", 1, ["dst_ip"]),
        )
        metrics = Metrics()
        store = AlertStore()
        runner = Runner(orchestrator, store=store, metrics=metrics)
        await runner.start()
        try:
            await runner.feed(make_event(1.0, "EVAL-FAIL-1"))
            await runner.feed(make_event(2.0, "EVAL-FAIL-2"))
            await runner.feed(make_event(3.0, "EVAL-AFTER-FAIL"))
            await wait_for(lambda: metrics.events_processed == 3)

            assert runner._task is not None
            assert not runner._task.done()
            assert metrics.detector_failures == 1
            assert metrics.events_received == metrics.events_processed == 3
            assert len(store.get_all()) == 1
        finally:
            await runner.stop()

    asyncio.run(run_stream())
