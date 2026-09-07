"""FastAPI application: REST API + WebSocket live alert delivery.

Endpoints:
    GET /health       status, uptime, registered detectors
    GET /alerts       all stored alerts
    GET /alerts/{id}  single alert (404 if missing)
    GET /stats        metrics snapshot
    WS  /ws           live alert stream
"""

import asyncio
import importlib
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect

from backend.orchestrator import Orchestrator
from backend.windowing import WindowConfig
from backend.store import AlertStore
from backend.metrics import Metrics
from backend.runner import Runner
from backend.malware_tls_features import MalwareTLSFeatureAdapter
from ml_engine.ddos.ddo_detector import DDoSDetector
from ml_engine.DNS_Tunelling.dns_tunnelling_detector import DNSTunnellingDetector
from ml_engine.mock.detector import MockDetector
from ml_engine.port_scanning.detector import PortScanDetector

C2BeaconingDetector = importlib.import_module(
    "ml_engine.C2 Beaconing.c2_beaconing_detector"
).C2BeaconingDetector
DGA_Detector = importlib.import_module(
    "ml_engine.DGA.dga_detector"
).DGADetector

ALERT_BUFFER_SIZE = int(os.getenv("ALERT_BUFFER_SIZE", "10000"))
ZEEK_LOG_DIR = os.getenv("ZEEK_LOG_DIR", "data_and_demo/zeek_logs")
REPLAY_ON_START = os.getenv("REPLAY_ON_START", "").lower() in ("1", "true", "yes")


def build_pipeline():
    """Construct the P3 pipeline with all production detectors."""
    store = AlertStore(max_size=ALERT_BUFFER_SIZE)
    metrics = Metrics()
    orch = Orchestrator()

    orch.register_detector(
        DDoSDetector(),
        WindowConfig("ddos", "tumbling", 60, ["dst_ip"]),
    )
    orch.register_detector(
        C2BeaconingDetector(),
        WindowConfig("c2", "tumbling", 60, ["src_ip", "dst_ip"]),
    )
    orch.register_detector(
        DGA_Detector(),
        WindowConfig("dga", "tumbling", 1, []),
    )
    orch.register_detector(
        DNSTunnellingDetector(),
        WindowConfig(
            "dns_tunnelling",
            "tumbling",
            60,
            ["src_ip", "dst_ip", "proto", "src_port", "dst_port"],
        ),
    )
    orch.register_detector(
        MalwareTLSFeatureAdapter(),
        WindowConfig(
            "malware_tls",
            "tumbling",
            60,
            ["src_ip", "dst_ip", "proto", "src_port", "dst_port"],
        ),
    )
    orch.register_detector(
        PortScanDetector(),
        WindowConfig("recon", "tumbling", 1, ["src_ip"]),
    )

    # Keep the Phase 4 mock path available for compatibility tests.
    orch.register_detector(
        MockDetector(),
        WindowConfig(
            detector_name="mock",
            window_type="tumbling",
            window_size_seconds=5,
            group_by=["dst_ip"],
        ),
    )
    runner = Runner(orchestrator=orch, store=store, metrics=metrics)
    return orch, store, metrics, runner


@asynccontextmanager
async def lifespan(app: FastAPI):
    await app.state.runner.start()
    if REPLAY_ON_START:
        n = await app.state.runner.replay_directory(ZEEK_LOG_DIR)
        print(f"[runner] replayed {ZEEK_LOG_DIR}: {n} alerts")
    yield
    await app.state.runner.stop()


app = FastAPI(title="SPECTRA", version="0.1.0", lifespan=lifespan)

orch, store, metrics, runner = build_pipeline()
app.state.orch = orch
app.state.store = store
app.state.metrics = metrics
app.state.runner = runner


@app.get("/health")
async def health():
    snap = app.state.metrics.snapshot()
    return {
        "status": "ok",
        "uptime_seconds": snap["uptime_seconds"],
        "detectors": app.state.orch.detector_registry.names(),
    }


@app.get("/alerts")
async def alerts():
    return app.state.store.get_all()


@app.get("/alerts/{alert_id}")
async def alert_detail(alert_id: str):
    alert = app.state.store.get(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="alert not found")
    return alert


@app.get("/stats")
async def stats():
    snap = app.state.metrics.snapshot()
    snap["alerts_in_store"] = len(app.state.store)
    return snap


@app.websocket("/ws")
async def ws_alerts(websocket: WebSocket):
    await websocket.accept()
    sub = await app.state.runner.subscribe()
    try:
        while True:
            payload = await sub.get()
            await websocket.send_text(payload)
    except WebSocketDisconnect:
        app.state.runner.unsubscribe(sub)
    except asyncio.CancelledError:
        app.state.runner.unsubscribe(sub)
        raise
