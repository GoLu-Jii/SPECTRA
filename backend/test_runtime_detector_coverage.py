import asyncio
from unittest.mock import Mock

from backend.main import build_pipeline
from backend.test_c2_integration import make_event as make_c2_event
from backend.test_dns_tunnelling_integration import make_event as make_dns_event
from backend.test_dns_tunnelling_integration import make_packet
from backend.test_malware_tls_integration import make_event as make_tls_event
from backend.test_malware_tls_integration import verdict as tls_verdict
from backend.test_port_scan_integration import make_event as make_port_event
from ml_engine.interface import Prediction


REQUIRED_THREAT_CLASSES = {
    "ddos": "DDoS",
    "c2": "BOTNET_C2_BEACONING",
    "dga": "DGA_DOMAIN",
    "dns_tunnelling": "DNS_TUNNELLING",
    "malware_tls": "MALWARE_TLS",
    "recon": "RECON_PORT_SCAN",
}
OPTIONAL_THREAT_CLASSES = {"exfiltration": "Data Exfiltration"}


def test_all_real_detectors_reach_runtime_alert_store_path():
    orch, store, metrics, runner = build_pipeline()
    detectors = {
        name: orch.detector_registry.get(name)
        for name in REQUIRED_THREAT_CLASSES
    }
    optional_detectors = {
        name: orch.detector_registry.get(name)
        for name in OPTIONAL_THREAT_CLASSES
    }

    assert set(orch.detector_registry.names()) >= set(REQUIRED_THREAT_CLASSES)
    assert all(detectors.values())
    assert set(name for name, detector in optional_detectors.items() if detector) <= set(
        optional_detectors
    )

    detectors["ddos"].predict = Mock(return_value={
        "detector": "DDoSDetector",
        "detected": True,
        "label": "DDoS",
        "confidence": 0.91,
        "severity": "CRITICAL",
        "evidence": {"source": "runtime-test"},
    })
    detectors["c2"].predict = Mock(return_value=(1, 0.92, {"source": "runtime-test"}))
    detectors["dga"].predict = Mock(return_value=(1, 0.93, {"source": "runtime-test"}))
    detectors["dns_tunnelling"].predict = Mock(
        return_value=(1, 0.94, {"source": "runtime-test"})
    )
    detectors["malware_tls"].classifier.assess = Mock(
        return_value=tls_verdict(0.95, True)
    )
    detectors["recon"].predict = Mock(return_value=Prediction(
        threat_class="RECON_PORT_SCAN",
        confidence=0.90,
        severity="HIGH",
        anomaly_zscore=2.5,
        evidence={"source": "runtime-test"},
    ))
    if optional_detectors["exfiltration"] is not None:
        optional_detectors["exfiltration"].predict = Mock(return_value=[
            {"prediction": 1, "confidence": 0.96, "label": "exfiltration"}
        ])

    events = [
        make_c2_event(1000.0, "C-COVERAGE-1"),
        make_c2_event(1010.0, "C-COVERAGE-2"),
        make_c2_event(1061.0, "C-COVERAGE-3"),
        make_dns_event(2000.0, make_packet(2000.0, True)),
        make_dns_event(2001.0, make_packet(2001.0, False)),
        make_tls_event(3000.0),
        make_tls_event(3061.0),
        make_port_event(),
        make_port_event(),
    ]
    events[-1] = type(events[-1])(
        **{**events[-1].__dict__, "ts": events[-1].ts + 2.0, "uid": "C-PORT-COVERAGE-2"}
    )
    if optional_detectors["exfiltration"] is not None:
        events.append(type(events[-2])(
            **{
                **events[-2].__dict__,
                "uid": "C-EXFIL-COVERAGE-1",
                "duration": 2.0,
                "orig_bytes": 1000,
                "resp_bytes": 500,
                "orig_pkts": 10,
                "resp_pkts": 5,
                "service": "ssl",
                "conn_state": "SF",
                "response_body_len": 0,
                "raw": {
                    "rate": 85.5,
                    "exfiltration_packet": {
                        "sttl": 64, "dttl": 60, "sloss": 0, "dloss": 0,
                        "sinpkt": 0.01, "dinpkt": 0.02, "sjit": 0.001,
                        "djit": 0.002, "swin": 65535, "dwin": 32768, "stcpb": 1000,
                        "dtcpb": 2000, "tcprtt": 0.03, "synack": 0.01,
                        "ackdat": 0.02,
                    },
                    "trans_depth": 1,
                    "is_ftp_login": 0,
                    "ct_ftp_cmd": 0,
                    "ct_flw_http_mthd": 0,
                },
            }
        ))

    async def replay():
        await runner.start()
        try:
            return await runner.replay_events(events)
        finally:
            await runner.stop()

    asyncio.run(replay())

    alerts = store.get_all()
    threat_classes = {
        alert.threat_classification.threat_class
        for alert in alerts
    }

    assert set(REQUIRED_THREAT_CLASSES.values()) <= threat_classes
    assert metrics.events_received == len(events)
    assert metrics.events_processed == len(events)

    for threat_class in REQUIRED_THREAT_CLASSES.values():
        matching = [
            alert for alert in alerts
            if alert.threat_classification.threat_class == threat_class
        ]
        assert matching
        alert = matching[0]
        assert 0.0 <= alert.scoring.confidence_score <= 1.0
        assert alert.scoring.severity.value
        assert alert.supporting_evidence

    detectors["ddos"].predict.assert_called()
    detectors["c2"].predict.assert_called()
    detectors["dga"].predict.assert_called()
    detectors["dns_tunnelling"].predict.assert_called()
    detectors["malware_tls"].classifier.assess.assert_called()
    detectors["recon"].predict.assert_called()
    if optional_detectors["exfiltration"] is not None:
        optional_detectors["exfiltration"].predict.assert_called()
