"""Phase 4 Verification Tests: API, store, metrics, runner, live delivery.

Covers:
  - AlertStore behavior (add/get/list/bounded)
  - Metrics tracking (counts, latencies, throughput)
  - Runner mock end-to-end (Zeek -> normalize -> window -> mock detector
    -> Prediction -> Alert -> store/live)
  - REST API endpoints (health, alerts, alerts/{id}, stats)
  - WebSocket live alert delivery
  + Regression: existing pipeline still imports and runs.
"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ZEEK_LOG_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data_and_demo", "zeek_logs",
)

passed = 0
failed = 0


def check(label, condition, detail=""):
    global passed, failed
    if condition:
        print(f"  [PASS] {label}")
        passed += 1
    else:
        print(f"  [FAIL] {label} -- {detail}")
        failed += 1


# ============================================================
# (1) AlertStore
# ============================================================
print("=" * 70)
print("TEST 1: AlertStore")
print("=" * 70)

from backend.store import AlertStore
from backend.schemas import (
    Alert, FlowIdentifier, ThreatClassification, Scoring, Severity, Protocol,
)
from datetime import datetime, timedelta


def make_alert(alert_id="ALT-00000001", ts=None):
    return Alert(
        alert_id=alert_id,
        timestamp=ts or datetime.now(),
        flow_identifier=FlowIdentifier(
            src_ip="1.1.1.1", dst_ip="10.0.0.1",
            src_port=1000, dst_port=80, protocol=Protocol.TCP,
        ),
        threat_classification=ThreatClassification(
            threat_class="MOCK_THREAT", mitre_tactic="Testing (TA9999)",
            mitre_technique_id="T9999.001", mitre_technique_name="Mock",
        ),
        scoring=Scoring(confidence_score=0.95, severity=Severity.MEDIUM,
                        anomaly_zscore=3.5),
        supporting_evidence={"reason": "test"},
    )


store = AlertStore(max_size=3)
a1 = make_alert("ALT-AAA1")
a2 = make_alert("ALT-AAA2")
a3 = make_alert("ALT-AAA3")
store.add(a1)
store.add(a2)
store.add(a3)
check("len() == 3", len(store) == 3)
check("get() returns by id", store.get("ALT-AAA2") is a2)
check("get() missing returns None", store.get("nope") is None)
check("get_all() returns all 3", len(store.get_all()) == 3)

# Bounded: adding 4th trims oldest (a1)
a4 = make_alert("ALT-AAA4")
store.add(a4)
check("bounded trim: len == 3", len(store) == 3)
check("bounded trim: oldest removed", store.get("ALT-AAA1") is None)
check("bounded trim: newest present", store.get("ALT-AAA4") is a4)

# ============================================================
# (2) Metrics
# ============================================================
print("\n" + "=" * 70)
print("TEST 2: Metrics")
print("=" * 70)

from backend.metrics import Metrics

m = Metrics()
m.events_received = 100
m.events_processed = 80
m.alerts_generated = 5
m.dropped_events = 2
m.set_queue_depth(3)
m.record_inference_latency(0.001)
m.record_inference_latency(0.003)
m.record_e2e_latency(0.01)

snap = m.snapshot()
check("snapshot has events_received", snap["events_received"] == 100)
check("snapshot has events_processed", snap["events_processed"] == 80)
check("snapshot has alerts_generated", snap["alerts_generated"] == 5)
check("snapshot has dropped_events", snap["dropped_events"] == 2)
check("snapshot has queue_depth", snap["queue_depth"] == 3)
check("snapshot throughput computed", snap["throughput_events_per_sec"] > 0)
check("inference latency avg", snap["inference_latency"]["avg_seconds"] == 0.002)
check("inference latency max", snap["inference_latency"]["max_seconds"] == 0.003)
check("e2e latency count", snap["end_to_end_latency"]["count"] == 1)
check("uptime present", snap["uptime_seconds"] >= 0)

# ============================================================
# (3) Runner mock end-to-end
# ============================================================
print("\n" + "=" * 70)
print("TEST 3: Runner Mock End-to-End")
print("=" * 70)

from backend.orchestrator import Orchestrator
from backend.windowing import WindowConfig
from ml_engine.mock.detector import MockDetector
from backend.ingestor import Ingestor
from backend.runner import Runner


async def runner_e2e():
    orch = Orchestrator()
    orch.register_detector(
        MockDetector(),
        WindowConfig(
            detector_name="mock", window_type="tumbling",
            window_size_seconds=5, group_by=["dst_ip"],
        ),
    )
    store = AlertStore()
    metrics = Metrics()
    runner = Runner(orchestrator=orch, store=store, metrics=metrics)
    await runner.start()

    ingestor = Ingestor()
    events = ingestor.ingest_directory(ZEEK_LOG_DIR)
    check(f"ingested {len(events)} demo events", len(events) > 0)

    n_alerts = await runner.replay_events(events)
    await runner.stop()

    check(f"replay generated {n_alerts} alerts", n_alerts > 0)
    check("alerts stored", len(store) == n_alerts)
    check("all processed", metrics.events_processed == len(events))
    check("received == processed", metrics.events_received == metrics.events_processed)
    check("alerts metric matches", metrics.alerts_generated == n_alerts)

    # Every stored alert is a valid standardized Alert
    all_valid = all(isinstance(a, Alert) for a in store.get_all())
    check("all alerts conform to Alert schema", all_valid)

    # Sample alert content
    sample = store.get_all()[0]
    check("sample has alert_id", sample.alert_id.startswith("ALT-"))
    check("sample has threat_class", sample.threat_classification.threat_class == "MOCK_THREAT")
    check("sample confidence in [0,1]", 0.0 <= sample.scoring.confidence_score <= 1.0)
    return n_alerts


asyncio.run(runner_e2e())

# ============================================================
# (4) REST API
# ============================================================
print("\n" + "=" * 70)
print("TEST 4: REST API")
print("=" * 70)

from fastapi.testclient import TestClient
import backend.main as bmain

with TestClient(bmain.app) as client:
    # health
    r = client.get("/health")
    check("GET /health -> 200", r.status_code == 200)
    body = r.json()
    check("health status ok", body.get("status") == "ok")
    check("health lists detectors", "mock" in body.get("detectors", []))

    # stats
    r = client.get("/stats")
    check("GET /stats -> 200", r.status_code == 200)
    s = r.json()
    check("stats has events_received", "events_received" in s)
    check("stats has alerts_in_store", "alerts_in_store" in s)

    # replay demo data through the running app pipeline
    ev = client.portal.call(
        bmain.app.state.runner.replay_events,
        Ingestor().ingest_directory(ZEEK_LOG_DIR),
    )
    check(f"app replay produced {ev} alerts", ev > 0)

    # alerts list
    r = client.get("/alerts")
    check("GET /alerts -> 200", r.status_code == 200)
    alerts = r.json()
    check("GET /alerts returns list", isinstance(alerts, list))
    check("GET /alerts non-empty", len(alerts) > 0)

    # alerts/{id}
    first_id = alerts[0]["alert_id"]
    r = client.get(f"/alerts/{first_id}")
    check("GET /alerts/{id} -> 200", r.status_code == 200)
    check("GET /alerts/{id} returns alert", r.json()["alert_id"] == first_id)

    # alerts/{id} 404
    r = client.get("/alerts/NOPE")
    check("GET /alerts/{id} missing -> 404", r.status_code == 404)

# ============================================================
# (5) WebSocket live delivery
# ============================================================
print("\n" + "=" * 70)
print("TEST 5: WebSocket Live Delivery")
print("=" * 70)


def ws_test():
    with TestClient(bmain.app) as client:
        with client.websocket_connect("/ws") as ws:
            # Inject a single demo event through the runner (runs in the
            # app's event loop) so the worker broadcasts an alert.
            events = Ingestor().ingest_directory(ZEEK_LOG_DIR)
            n = client.portal.call(bmain.app.state.runner.replay_events, events[:1])
            data = ws.receive_text()
            assert n > 0, "expected at least one alert from replay"
            payload = __import__("json").loads(data)
            check("WS received an alert message", "alert_id" in payload)
            check("WS alert is standardized", "threat_classification" in payload)
            check("WS alert has scoring", "scoring" in payload)


try:
    ws_test()
except Exception as e:
    import traceback
    traceback.print_exc()
    check(f"WebSocket test ran (error: {e})", False, str(e))

# ============================================================
# (6) Regression: pipeline imports intact
# ============================================================
print("\n" + "=" * 70)
print("TEST 6: Pipeline Regression")
print("=" * 70)

from backend.schemas import Severity, Protocol
from backend.ingestor import NormalizedEvent
from backend.windowing import WindowManager, WindowConfig
from backend.orchestrator import Orchestrator, AlertGenerator
from ml_engine.interface import BaseThreatDetector, Prediction
from ml_engine.mock.detector import MockDetector

check("Severity enum intact", len(Severity) == 4)
check("Protocol enum intact", len(Protocol) == 3)
check("MockDetector is BaseThreatDetector", issubclass(MockDetector, BaseThreatDetector))

# ============================================================
# SUMMARY
# ============================================================
print("\n" + "=" * 70)
print("PHASE 4 VERIFICATION SUMMARY")
print("=" * 70)
print(f"  Passed: {passed}")
print(f"  Failed: {failed}")
print(f"  Total:  {passed + failed}")
print()
print("  ALL TESTS PASSED" if failed == 0 else "  SOME TESTS FAILED")

sys.exit(1 if failed > 0 else 0)
