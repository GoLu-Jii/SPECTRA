"""Reproducible passive replay evaluation for the production pipeline."""

from __future__ import annotations

import asyncio
import time
import uuid
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Dict, Tuple

from backend.ingestor import Ingestor
from backend.metrics import Metrics
from backend.orchestrator import Orchestrator
from backend.runner import Runner
from backend.store import AlertStore

Pipeline = Tuple[Orchestrator, AlertStore, Metrics, Runner]
PipelineFactory = Callable[[], Pipeline]


def _default_pipeline_factory() -> Pipeline:
    from backend.main import build_pipeline

    return build_pipeline()


class ReplayEvaluator:
    """Run a passive Zeek-directory replay through a fresh production pipeline."""

    def __init__(
        self,
        zeek_dir: str | Path,
        pipeline_factory: PipelineFactory | None = None,
    ) -> None:
        self.zeek_dir = Path(zeek_dir)
        self.pipeline_factory = pipeline_factory or _default_pipeline_factory

    def run(self) -> Dict[str, Any]:
        run_id = uuid.uuid4().hex

        started_at = time.perf_counter()
        summary = asyncio.run(self._run_pipeline(run_id, started_at))
        return summary

    async def _run_pipeline(
        self,
        run_id: str,
        started_at: float,
    ) -> Dict[str, Any]:
        _, store, metrics, runner = self.pipeline_factory()
        events = Ingestor(metrics=metrics).ingest_directory(str(self.zeek_dir))
        await runner.start()
        try:
            await runner.replay_events(events)
            runtime_duration = max(time.perf_counter() - started_at, 1e-9)
            metrics_snapshot = metrics.snapshot()
            worker_alive = runner._task is not None and not runner._task.done()
            alerts = store.get_all()
            return self._summary(
                run_id,
                runtime_duration,
                len(events),
                worker_alive,
                metrics_snapshot,
                alerts,
            )
        finally:
            await runner.stop()

    def _summary(
        self,
        run_id: str,
        runtime_duration: float,
        event_count: int,
        worker_alive: bool,
        metrics_snapshot: Dict[str, Any],
        alerts,
    ) -> Dict[str, Any]:
        threat_counts = Counter(
            alert.threat_classification.threat_class for alert in alerts
        )
        severity_counts = Counter(
            alert.scoring.severity.value for alert in alerts
        )
        confidences = [
            float(alert.scoring.confidence_score) for alert in alerts
        ]
        processed = metrics_snapshot["events_processed"]

        return {
            "run_id": run_id,
            "source": {
                "type": "zeek_directory",
                "path": str(self.zeek_dir),
                "event_count": event_count,
            },
            "runtime": {
                "started": True,
                "completed": True,
                "worker_alive_after_drain": worker_alive,
                "replay_duration_seconds": round(runtime_duration, 6),
                "events_received": metrics_snapshot["events_received"],
                "events_processed": processed,
                "dropped_events": metrics_snapshot["dropped_events"],
                "detector_failures": metrics_snapshot["detector_failures"],
                "queue_depth": metrics_snapshot["queue_depth"],
            },
            "performance": {
                "events_per_second": round(processed / runtime_duration, 4),
                "inference_latency": metrics_snapshot["inference_latency"],
                "end_to_end_latency": metrics_snapshot["end_to_end_latency"],
            },
            "alerts": {
                "total": len(alerts),
                "by_threat_class": dict(sorted(threat_counts.items())),
                "by_severity": dict(sorted(severity_counts.items())),
                "confidence": {
                    "min": min(confidences) if confidences else None,
                    "max": max(confidences) if confidences else None,
                    "average": sum(confidences) / len(confidences) if confidences else None,
                },
            },
            "ground_truth": {
                "available": False,
                "accuracy_metrics": None,
            },
        }


def evaluate_zeek_directory(
    zeek_dir: str | Path,
    pipeline_factory: PipelineFactory | None = None,
) -> Dict[str, Any]:
    """Evaluate one Zeek directory through a fresh production pipeline."""
    return ReplayEvaluator(zeek_dir, pipeline_factory).run()
