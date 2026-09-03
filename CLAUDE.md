# SPECTRA: Cybersecurity Threat Detection System

**Project Type:** Three-day prototype | **Team Size:** 6 people | **Language:** Python (backend), TypeScript (frontend)

## Project Overview

SPECTRA is a real-time network threat detection system that ingests Zeek logs, extracts features, runs six machine learning detectors in parallel, and streams alerts to a dashboard. The system is passive, read-only, and designed for streaming inference on network traffic.

### Architecture Layers

```
Traffic → Zeek Logs → Ingestion → Normalization → Feature Extraction → 
  Detectors (P1/P2) → Orchestration → Alert Schema → Streaming → API → Dashboard
```

---

## Team Ownership & Responsibilities

### P1 — Flow/Behavior ML Engineer
**Detectors:**
- DDoS (volumetric protocol attacks)
- Reconnaissance / Port Scanning
- Data Exfiltration

**Constraint:** Implement `detector.py` that inherits `BaseThreatDetector` from `ml_engine/interface.py`.

---

### P2 — Protocol/Temporal ML Engineer
**Detectors:**
- Botnet C2 Beaconing (periodic command & control signaling)
- DGA Detection (domain generation algorithms)
- DNS Tunnelling (covert exfiltration over DNS)
- TLS/QUIC Malware Detection (encrypted malware C2 via JA4 fingerprinting)

**Constraint:** Implement `detector.py` that inherits `BaseThreatDetector` from `ml_engine/interface.py`.

---

### P3 — System / Streaming / Integration Engineer
**My Responsibilities:**
- **Passive Ingestion:** Tail Zeek logs, parse events into structured records
- **Normalization:** Convert raw Zeek fields into canonical feature names
- **Streaming Infrastructure:** Real-time message passing (alert + flow data)
- **Common Feature Infrastructure:** Shared time-window aggregations, rolling statistics
- **Model Integration:** Load and orchestrate all six detectors
- **Inference Orchestration:** Execute detectors on normalized features, handle batching
- **Alert Generation:** Convert detector predictions into standardized alert objects
- **Alert Schema:** Define Pydantic models for alerts, flows, threats, and scoring
- **API Endpoints:** REST (health, config, test) + WebSocket (live alerts + flows)
- **Deployment:** Docker Compose configuration, environment setup
- **End-to-End Integration:** Wire all components together, verify data flow

**Primary Working Area:** `backend/` (main.py, ingestor.py, orchestrator.py, schemas.py)

**Secondary Areas (P3 may modify when required for integration):**
- `ml_engine/interface.py` — Define `BaseThreatDetector` contract
- `docker-compose.yml` — Service orchestration
- `backend/Dockerfile` — Container build
- `backend/requirements.txt` — Python dependencies
- Test files — Integration and end-to-end tests
- Deployment configuration

**Constraint:** Do not modify P1/P2 detector implementations unless explicitly asked.

---

### P4 — Data / Demo / Replay
**Responsibilities:**
- Generate demo PCAP files
- Create mock alert datasets for frontend testing
- Provide replay tools (Zeek log generation)

---

### P5 — Frontend / Dashboard
**Responsibilities:**
- React-based dashboard
- Real-time alert visualization
- WebSocket client for live streaming
- Flow and threat display

---

### P6 — QA / Testing / Demo
**Responsibilities:**
- Integration tests
- Demo scenario execution
- Performance validation
- Final presentation

---

## Architectural Constraints

### Passivity & Safety
- ✅ **Read-only traffic analysis** — never modify or inspect plaintext
- ✅ **No active probing** — system is entirely passive
- ✅ **No return path to production** — all analysis is one-way
- ✅ **No handshake initiated by monitoring** — system never reaches out to traffic sources
- ✅ **No traffic blocking or modification** — pure observation only

### Protocol Analysis
- ✅ **TLS/QUIC metadata-only** — analyze packet sizes, timing, JA4 fingerprints, but never decrypt payloads
- ✅ **Zeek log extraction** — rely on Zeek's native protocol parsing for all other protocols

### Processing Model
- ✅ **Streaming/incremental** — process events as they arrive, not batch at end-of-run
- ✅ **Time-windowed aggregations** — rolling 60-second windows for behavioral signals
- ✅ **Minimal state retention** — drop old windows after processing

### Alert Format
All alerts must include:
- `alert_id` — Unique identifier
- `timestamp` — RFC 3339 ISO 8601 (UTC)
- `flow_identifier` — src_ip, dst_ip, src_port, dst_port, protocol
- `threat_classification` — threat_class, MITRE tactic, technique_id, technique_name
- `scoring` — confidence_score (0–1), severity (LOW/MEDIUM/HIGH/CRITICAL), anomaly_zscore
- `supporting_evidence` — Detector-specific features that justify the alert

Reference: `data_and_demo/mock_alerts.json`

### Performance Targets
- **Throughput:** Process Zeek logs in real-time (< 1 sec latency to alert)
- **Latency:** Alert available on WebSocket within 2–3 seconds of event ingestion
- **Scalability:** Design for 1000s of concurrent flows (prototype scope: 100s)

---

## Repository Structure

```
.
├── README.md                        # Setup instructions
├── CLAUDE.md                        # This file — project architecture & rules
├── docker-compose.yml               # Service orchestration (P3)
│
├── backend/                         # P3: Core FastAPI pipeline
│   ├── main.py                      # API endpoints, WebSocket server
│   ├── ingestor.py                  # Zeek log tailing, event parsing
│   ├── orchestrator.py              # Detector orchestration, inference
│   ├── schemas.py                   # Pydantic models (alerts, flows, threats)
│   ├── requirements.txt              # Python dependencies
│   └── Dockerfile                   # Container build
│
├── ml_engine/                       # P1 & P2: ML detector implementations
│   ├── interface.py                 # BaseThreatDetector contract (P3 defines)
│   ├── ddos/                        # P1's detector
│   │   ├── detector.py              # DDoS detector class
│   │   ├── ddos_model.pkl           # Serialized model
│   │   └── train_ddos.ipynb         # Training notebook
│   ├── recon/                       # P1's detector
│   ├── exfiltration/                # P1's detector
│   ├── beaconing/                   # P2's detector
│   ├── dns_tunnelling/              # P2's detector
│   └── tls_malware/                 # P2's detector
│
├── frontend/                        # P5: React dashboard
│   ├── src/
│   ├── package.json
│   └── vite.config.ts
│
├── data_and_demo/                   # P4: Test data & replay tools
│   ├── demo_traffic.pcap            # Demo network traffic
│   ├── generate_demo_pcap.py        # PCAP generation script
│   ├── generate_zeek_logs.py        # Zeek log generation script
│   ├── mock_alerts.json             # Static alert examples
│   └── zeek_logs/                   # Live output directory (runtime)
│
└── tests/                           # P6: Integration & end-to-end tests
```

---

## Development Rules

### General Principles
1. **Inspect before modifying** — Always read existing code and understand the architecture before making changes.
2. **Explain large changes** — For multi-file changes, outline the approach first and wait for approval before implementing.
3. **Build incrementally** — Test each layer as it's implemented (ingestion → normalization → orchestration → API).
4. **Reuse over duplicate** — Extend existing interfaces rather than creating parallel systems.
5. **Keep it simple** — Prefer straightforward solutions suitable for a three-day prototype; avoid over-engineering.
6. **No unnecessary infrastructure** — Kubernetes, distributed queues, and microservices are out of scope.

### Code Style & Interfaces
1. **Generic integration interfaces** — Design P3 interfaces so P1/P2 detectors can plug in without modification.
2. **Standardized detector contract** — `BaseThreatDetector` in `ml_engine/interface.py` defines how all detectors work.
3. **Typed schemas** — Use Pydantic for all data structures; alerts must match the schema in `data_and_demo/mock_alerts.json`.
4. **Logging & observability** — Include debug logs for data flow; make it easy to trace an event through the pipeline.

### Team Collaboration
1. **Do not modify P1/P2 detectors** — Only P3 may change `ml_engine/interface.py` and orchestration.
2. **P1/P2 must inherit from `BaseThreatDetector`** — The interface is the contract; P3 defines it, P1/P2 implement it.
3. **Communicate design changes** — If the detector interface needs a breaking change, notify the team before implementing.
4. **Integration checkpoints** — Verify each detector can load and run end-to-end before final testing.

### Testing & Verification
1. **No silent failures** — If a detector fails to load, the orchestrator must error clearly.
2. **Mock detector fallback** — For testing P3 before P1/P2 finish, use a simple mock detector.
3. **End-to-end test** — Before demo, verify: Zeek logs → ingestion → normalization → orchestration → alert → WebSocket.
4. **Demo reproducibility** — Alerts must be deterministic; use replay tools from P4 to test.

---

## Implementation Priority (P3)

**Phase 1: Foundation (Alert Schema & Detector Interface)**
1. Define `schemas.py` — Pydantic models for alerts, flows, threats, scoring, evidence
2. Define `ml_engine/interface.py` — `BaseThreatDetector` abstract base class
3. Create mock detector for testing

**Phase 2: Ingestion & Normalization**
4. Implement `ingestor.py` — Tail zeek_logs/, parse JSON events, buffer into time-windows
5. Normalize Zeek fields into canonical feature names
6. Create test data with sample Zeek logs

**Phase 3: Orchestration & Inference**
7. Implement `orchestrator.py` — Load all detectors, execute predictions, generate alerts
8. Handle detector failures gracefully
9. Test with mock detector first, then integrate real detectors

**Phase 4: Streaming & API**
10. Implement `main.py` — FastAPI app with REST endpoints + WebSocket server
11. Stream alerts and flows to connected clients
12. Add health check and configuration endpoints

**Phase 5: Deployment & Integration**
13. Configure `docker-compose.yml` — Backend service, frontend service, data volume
14. Document environment setup
15. End-to-end integration test
16. Performance validation

---

## Data Flow

### Ingestion Path
```
Zeek Logs (JSON) 
  → Ingestor (tail + parse) 
  → Raw Event Record 
  → Buffer (60-sec time-window)
  → Emit to Orchestrator
```

### Processing Path
```
Raw Event 
  → Normalize (canonical field names) 
  → Aggregate Features (rolling stats) 
  → Feature Vector 
  → Detector.predict() 
  → Prediction Confidence & Class
```

### Alert Path
```
Prediction + Raw Event 
  → Alert Generator 
  → Alert Object (schemas.py) 
  → JSON Serialization 
  → WebSocket Broadcast 
  → Dashboard Render
```

---

## Configuration & Environment

### Required Environment Variables
- `ZEEK_LOG_DIR` — Path to zeek_logs/ directory (default: `./data_and_demo/zeek_logs`)
- `LOG_LEVEL` — Debug/Info/Warning/Error (default: Info)
- `ALERT_BUFFER_SIZE` — Max alerts to hold in memory (default: 10000)
- `WINDOW_SIZE_SEC` — Time-window for aggregations (default: 60)

### Dependencies
See `backend/requirements.txt` for a complete list. Key packages:
- `fastapi` — Web framework
- `uvicorn` — ASGI server
- `pydantic` — Data validation
- `websockets` — Real-time streaming
- `numpy` / `scipy` — Feature computation
- `scikit-learn` — Model loading (pickle format)

---

## References

- **Alert Schema:** `data_and_demo/mock_alerts.json`
- **MITRE Framework:** [MITRE ATT&CK](https://attack.mitre.org/)
- **JA4 Fingerprinting:** [JA4 TLS Fingerprinting](https://github.com/FoxIO-LLC/ja4)
- **Zeek Documentation:** [Zeek NSM](https://zeek.org/)
- **FastAPI:** [FastAPI Docs](https://fastapi.tiangolo.com/)

---

## Questions?

- **P1/P2:** How should your detectors report confidence and anomaly scores?
- **P4:** What format should replay tools output for testing?
- **P5:** How should the dashboard subscribe to WebSocket alerts?
- **P6:** What are the key acceptance criteria for demo?

---

**Last Updated:** 2026-09-03  
**Version:** 1.0  
**Status:** Active Development
