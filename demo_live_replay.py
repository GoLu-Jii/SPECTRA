"""DEMO/TEST ONLY: run the real FastAPI app and replay after a WS client connects.

This launcher must not be used as a production entry point. It imports the
existing backend app and runner, starts them in one process, waits for the
existing WebSocket handler to register a subscriber, and then invokes the
existing runner.replay_directory() method. No API endpoint or second pipeline
is created.
"""

from __future__ import annotations

import argparse
import asyncio
import os
from pathlib import Path

# Disable startup replay before importing backend.main, where this setting is read.
os.environ["REPLAY_ON_START"] = "false"

import uvicorn

from backend.main import app
from backend.ingestor import Ingestor


def load_chronological_events(zeek_dir: Path):
    """Load existing Zeek telemetry and restore global timestamp order."""
    events = Ingestor(metrics=app.state.runner.metrics).ingest_directory(str(zeek_dir))
    return sorted(events, key=lambda event: event.ts)


async def replay_after_websocket_connect(
    zeek_dir: Path,
    timeout_seconds: float,
) -> None:
    runner = app.state.runner
    deadline = asyncio.get_running_loop().time() + timeout_seconds

    print("[demo] waiting for FastAPI readiness and a connected WebSocket client")
    while asyncio.get_running_loop().time() < deadline:
        # The production app has no client-ready callback. This demo-only
        # launcher observes the subscriber registered by the existing /ws handler.
        if runner.is_ready() and runner._subscribers:
            print("[demo] WebSocket subscriber detected; replaying demo Zeek events")
            events = load_chronological_events(zeek_dir)
            print(f"[demo] replaying {len(events)} normalized events in timestamp order")
            alert_count = await runner.replay_events(events)
            print(f"[demo] replay complete: {alert_count} new alerts generated")
            return
        await asyncio.sleep(0.25)

    print(f"[demo] timed out after {timeout_seconds:g}s without a WebSocket client")


async def run(args: argparse.Namespace) -> None:
    config = uvicorn.Config(
        app,
        host=args.host,
        port=args.port,
        log_level="info",
    )
    server = uvicorn.Server(config)
    replay_task = asyncio.create_task(
        replay_after_websocket_connect(Path(args.zeek_dir), args.timeout)
    )

    try:
        await server.serve()
    finally:
        replay_task.cancel()
        await asyncio.gather(replay_task, return_exceptions=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="DEMO/TEST ONLY: replay real Zeek events after a browser WS connection"
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument(
        "--zeek-dir",
        default="data_and_demo/zeek_logs",
        help="Existing Zeek fixture directory to replay",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=300,
        help="Seconds to wait for a browser WebSocket before skipping replay",
    )
    return parser.parse_args()


if __name__ == "__main__":
    try:
        asyncio.run(run(parse_args()))
    except KeyboardInterrupt:
        print("[demo] stopped")
