import json
from unittest.mock import Mock

from fastapi.testclient import TestClient

import backend.main as main
from backend.main import build_pipeline
from backend.test_c2_integration import make_event as make_c2_event
from backend.test_dns_tunnelling_integration import make_event as make_dns_event
from backend.test_dns_tunnelling_integration import make_packet
from backend.test_malware_tls_integration import make_event as make_tls_event
from backend.test_malware_tls_integration import verdict as tls_verdict
from backend.test_port_scan_integration import make_event as make_port_event
from ml_engine.interface import Prediction


def _runtime_alerts():
    orchestrator, store, metrics, runner = build_pipeline()
    detectors = {
        name: orchestrator.detector_registry.get(name)
        for name in ("ddos", "c2", "dga", "dns_tunnelling", "malware_tls", "recon")
    }

    detectors["ddos"].predict = Mock(return_value={
        "detector": "DDoSDetector",
        "detected": True,
        "label": "DDoS",
        "confidence": 0.91,
        "severity": "CRITICAL",
        "evidence": {"source": "api-test"},
    })
    detectors["c2"].predict = Mock(return_value=(1, 0.92, {"source": "api-test"}))
    detectors["dga"].predict = Mock(return_value=(1, 0.93, {"source": "api-test"}))
    detectors["dns_tunnelling"].predict = Mock(
        return_value=(1, 0.94, {"source": "api-test"})
    )
    detectors["malware_tls"].classifier.assess = Mock(
        return_value=tls_verdict(0.95, True)
    )
    detectors["recon"].predict = Mock(return_value=Prediction(
        threat_class="RECON_PORT_SCAN",
        confidence=0.90,
        severity="HIGH",
        anomaly_zscore=2.5,
        evidence={"source": "api-test"},
    ))

    port_first = make_port_event()
    port_second = type(port_first)(
        **{
            **port_first.__dict__,
            "ts": port_first.ts + 2.0,
            "uid": "C-API-PORT-2",
        }
    )
    events = [
        make_c2_event(1000.0, "C-API-C2-1"),
        make_c2_event(1010.0, "C-API-C2-2"),
        make_c2_event(1061.0, "C-API-C2-3"),
        make_dns_event(2000.0, make_packet(2000.0, True)),
        make_dns_event(2001.0, make_packet(2001.0, False)),
        make_dns_event(2061.0, make_packet(2061.0, True)),
        make_tls_event(3000.0),
        make_tls_event(3061.0),
        port_first,
        port_second,
    ]

    alerts = orchestrator.process_events(events)
    alerts.extend(orchestrator.flush_windows())
    for alert in alerts:
        store.add(alert)
    return orchestrator, store, metrics, runner, alerts


def _install_pipeline(pipeline):
    orchestrator, store, metrics, runner = pipeline[:4]
    main.app.state.orch = orchestrator
    main.app.state.store = store
    main.app.state.metrics = metrics
    main.app.state.runner = runner


def test_api_contract_and_six_detector_alert_serialization():
    pipeline = _runtime_alerts()
    orchestrator, store, metrics, runner, alerts = pipeline
    _install_pipeline(pipeline)

    expected = {
        "DDoS", "BOTNET_C2_BEACONING", "DGA_DOMAIN",
        "DNS_TUNNELLING", "MALWARE_TLS", "RECON_PORT_SCAN",
    }
    response_payloads = []

    with TestClient(main.app) as client:
        health = client.get("/health")
        assert health.status_code == 200
        health_body = health.json()
        assert health_body["status"] == "ok"
        assert set(health_body["detectors"]) >= {"ddos", "c2", "dga", "dns_tunnelling", "malware_tls", "recon"}

        stats = client.get("/stats")
        assert stats.status_code == 200
        stats_body = stats.json()
        assert {
            "events_received", "events_processed", "dropped_events", "queue_depth",
            "throughput_events_per_sec", "inference_latency", "end_to_end_latency",
            "alerts_in_store",
        } <= stats_body.keys()
        assert stats_body["alerts_in_store"] == len(alerts)
        assert json.dumps(stats_body)

        listed = client.get("/alerts")
        assert listed.status_code == 200
        response_payloads = listed.json()
        assert len(response_payloads) == len(alerts)
        assert len({item["alert_id"] for item in response_payloads}) == len(response_payloads)

        returned_classes = set()
        for payload in response_payloads:
            assert payload["alert_id"]
            assert payload["timestamp"]
            assert payload["flow_identifier"]
            assert payload["threat_classification"]["threat_class"]
            assert 0.0 <= payload["scoring"]["confidence_score"] <= 1.0
            assert payload["scoring"]["severity"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
            assert payload["supporting_evidence"]
            returned_classes.add(payload["threat_classification"]["threat_class"])

            detail = client.get(f"/alerts/{payload['alert_id']}")
            assert detail.status_code == 200
            assert detail.json() == payload
            assert json.dumps(detail.json())

        assert expected <= returned_classes
        assert client.get("/alerts/DOES-NOT-EXIST").status_code == 404


def test_empty_alert_store_returns_empty_json_list():
    pipeline = build_pipeline()
    _install_pipeline(pipeline)

    with TestClient(main.app) as client:
        response = client.get("/alerts")
        assert response.status_code == 200
        assert response.json() == []
        assert client.get("/alerts/DOES-NOT-EXIST").status_code == 404
