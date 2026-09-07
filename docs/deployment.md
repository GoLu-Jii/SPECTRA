# SPECTRA Backend Deployment

This deployment runs the existing FastAPI backend and its passive Zeek replay path. It does not initiate network probes, handshakes, blocking, mitigation, or outbound service calls.

## Build and run

From the repository root:

```powershell
docker compose build
docker compose up
```

The API is published on `http://127.0.0.1:8000`. Only the existing API port is published.

The Compose service replays the read-only fixture directory on startup:

```text
./data_and_demo/zeek_logs -> /data/zeek_logs:ro
```

Readiness is reported by the existing `GET /health` endpoint. The Compose healthcheck succeeds only when the response contains `"ready": true`, after startup replay has completed and the Runner worker is alive.

## Runtime restrictions

- The image runs as UID/GID `10001`, not root.
- The container filesystem is read-only.
- `/data/zeek_logs` is mounted read-only.
- `/tmp` is the only writable location, provided as a bounded tmpfs with `noexec`, `nosuid`, and `nodev`.
- `no-new-privileges` is enabled.
- All Linux capabilities are dropped.
- No privileged mode, host networking, devices, databases, or external services are configured.
- The Docker network is marked `internal` to prevent normal outbound connectivity from the service.

These settings provide container-level restrictions. They do not establish a physical one-way data diode or infrastructure-level network isolation.

## Configuration

Compose supplies these supported application settings:

| Variable | Compose default | Purpose |
| --- | --- | --- |
| `ZEEK_LOG_DIR` | `/data/zeek_logs` | Passive Zeek log directory |
| `EVENT_QUEUE_MAX_SIZE` | `1000` | Maximum queued events |
| `RUNNER_SHUTDOWN_TIMEOUT_SECONDS` | `5` | Graceful shutdown drain timeout |
| `SUBSCRIBER_QUEUE_MAX_SIZE` | `100` | Per-WebSocket subscriber queue bound |
| `ENABLE_MOCK_DETECTOR` | `false` | Keep test detector out of production alerts |
| `REPLAY_ON_START` | `true` | Replay the mounted demo logs during startup |

The application also supports `ALERT_BUFFER_SIZE`; Compose leaves its application default unchanged.

## Filesystem audit

The backend keeps alerts and metrics in memory. Evaluation output is written only when the standalone evaluator is explicitly given an output path, and that CLI is not the container startup command. Model artifacts are loaded read-only from the image. Python bytecode is disabled with `PYTHONDONTWRITEBYTECODE=1`.

## Shutdown and limitations

The Runner stops accepting new events, drains queued work up to its configured timeout, accounts for abandoned events, and then cancels the worker. Docker stop therefore has a bounded shutdown path.

The deployment has been statically validated and smoke-tested where Docker is available. Docker itself cannot prove a physical one-way monitoring enclave; that remains an infrastructure responsibility outside this repository.
