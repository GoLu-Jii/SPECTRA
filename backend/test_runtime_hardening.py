import asyncio
import time
from datetime import datetime
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

import backend.main as main
from backend.ingestor import Ingestor, NormalizedEvent
from backend.metrics import Metrics
from backend.orchestrator import Orchestrator
from backend.runner import Runner
from backend.schemas import Alert, FlowIdentifier, Protocol, Scoring, Severity, ThreatClassification
from backend.store import AlertStore
from backend.windowing import WindowConfig
from ml_engine.mock.detector import MockDetector


def make_event(timestamp=1.0, uid="HARDENING-1"):
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


def make_alert(alert_id):
    return Alert(
        alert_id=alert_id,
        timestamp=datetime.now(),
        flow_identifier=FlowIdentifier(
            src_ip="192.0.2.10", dst_ip="198.51.100.20",
            src_port=40000, dst_port=443, protocol=Protocol.TCP,
        ),
        threat_classification=ThreatClassification(
            threat_class="MOCK_THREAT", mitre_tactic="Testing",
            mitre_technique_id="T9999", mitre_technique_name="Test",
        ),
        scoring=Scoring(confidence_score=0.9, severity=Severity.HIGH, anomaly_zscore=1.0),
        supporting_evidence={"test": True},
    )


async def wait_for(condition, timeout=2.0):
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() >= deadline:
            raise AssertionError("condition was not reached before timeout")
        await asyncio.sleep(0.001)


class SlowDetector(MockDetector):
    def predict(self, features, context):
        time.sleep(0.2)
        return super().predict(features, context)


class FailingDetector(MockDetector):
    def predict(self, features, context):
        raise RuntimeError("flush failure")


def build_runner(detector=None, **kwargs):
    orchestrator = Orchestrator()
    orchestrator.register_detector(
        detector or MockDetector(),
        WindowConfig("mock", "tumbling", 60, ["dst_ip"]),
    )
    metrics = Metrics()
    store = AlertStore()
    return Runner(orchestrator, store=store, metrics=metrics, **kwargs), metrics, store


def test_production_pipeline_gates_mock_detector():
    default_orch, _, _, _ = main.build_pipeline(include_mock=False)
    test_orch, _, _, _ = main.build_pipeline(include_mock=True)

    assert "mock" not in default_orch.detector_registry.names()
    assert "mock" in test_orch.detector_registry.names()
    assert {
        "ddos", "c2", "dga", "dns_tunnelling", "malware_tls", "recon",
    } <= set(default_orch.detector_registry.names())


def test_runner_configuration_is_validated():
    with pytest.raises(ValueError):
        build_runner(max_queue=0)
    with pytest.raises(ValueError):
        build_runner(shutdown_timeout=0)
    with pytest.raises(ValueError):
        build_runner(subscriber_queue_size=0)


def test_health_reports_running_and_stopped_worker():
    with TestClient(main.app) as client:
        ready = client.get("/health").json()
        assert ready["status"] == "ok"
        assert ready["initialized"] is True
        assert ready["ready"] is True
        assert ready["worker_state"] == "running"
        assert ready["startup_replay_complete"] is True

        client.portal.call(main.app.state.runner.stop)
        stopped = client.get("/health").json()
        assert stopped["status"] == "not_ready"
        assert stopped["ready"] is False
        assert stopped["worker_state"] == "stopped"


def test_shutdown_accounts_for_queued_events():
    async def run_shutdown():
        runner, metrics, _ = build_runner(
            shutdown_timeout=0.001, max_queue=20000,
        )
        await runner.start()
        for index in range(10000):
            await runner.feed(make_event(float(index), f"SHUTDOWN-{index}"))
        await runner.stop()

        assert runner._task is None
        assert metrics.abandoned_events > 0
        assert metrics.queue_depth == 0
        assert metrics.events_received == metrics.events_processed + metrics.abandoned_events

    asyncio.run(run_shutdown())


def test_full_subscriber_is_removed_without_blocking_runner():
    async def run_broadcast():
        runner, _, _ = build_runner(subscriber_queue_size=1)
        subscriber = await runner.subscribe()
        await runner._broadcast(make_alert("ALERT-1"))
        await runner._broadcast(make_alert("ALERT-2"))

        assert subscriber not in runner._subscribers

    asyncio.run(run_broadcast())



def test_malformed_zeek_record_is_quarantined(tmp_path, caplog):
    log = tmp_path / "conn.log"
    log.write_text(
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
        "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\n"
        "1.0\tVALID\t192.0.2.1\t40000\t198.51.100.1\t443\ttcp\n"
        "not-a-time\tBAD\t192.0.2.2\t40001\t198.51.100.2\t443\ttcp\n",
        encoding="utf-8",
    )
    metrics = Metrics()
    events = Ingestor(metrics=metrics).ingest_directory(str(tmp_path))

    assert [event.uid for event in events] == ["VALID"]
    assert metrics.malformed_events == 1
    assert any("Quarantined malformed Zeek record" in record.message for record in caplog.records)


def test_final_flush_failure_isolated_and_counted():
    async def run_flush():
        runner, metrics, _ = build_runner(detector=FailingDetector())
        await runner.start()
        try:
            await runner.feed(make_event())
            await wait_for(lambda: metrics.events_processed == 1)
            alerts = await runner.replay_events([])

            assert alerts == 0
            assert metrics.detector_failures == 1
            assert runner._task is not None
            assert not runner._task.done()
        finally:
            await runner.stop()

    asyncio.run(run_flush())
