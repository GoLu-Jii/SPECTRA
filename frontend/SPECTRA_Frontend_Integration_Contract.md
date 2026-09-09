# SPECTRA — Frontend Integration Contract

Source of truth for how the dashboard talks to the P3 backend. Frontend integrates against this contract — it does not invent its own alert schema, detection logic, confidence, or severity calculations.

---

## 1. Architecture

```
                    SPECTRA BACKEND
                         |
        +----------------+----------------+
        |                                 |
   ML / Streaming                     Alert Store
        |                                 |
        +--------------+------------------+
                       |
                FastAPI Backend
                       |
        +--------------+--------------+
        |              |              |
      REST           REST          WebSocket
     /health        /stats          /ws
     /alerts
     /alerts/{id}
        |              |              |
        +--------------+--------------+
                       v
                 FRONTEND DASHBOARD
```

Frontend does **not** need to know:
- how DDoS / C2 / DGA / TLS features are calculated
- which model file is loaded (XGBoost, Random Forest, SVM — irrelevant to frontend)
- how WindowManager, Runner, or detector registration works
- how inference happens internally

Frontend only consumes the **output contract** below.

---

## 2. Endpoints

```
GET  /health
GET  /stats
GET  /alerts
GET  /alerts/{id}
WS   /ws
```

Verify all of these against the real running backend before building against them:

```
curl http://localhost:8000/health
curl http://localhost:8000/stats
curl http://localhost:8000/alerts
```

```
ws://localhost:8000/ws
```

Use the **actual returned JSON** as the source of truth for field names — not this document, not memory, not assumption.

---

## 3. `GET /health`

Determines whether the backend is actually ready — HTTP 200 does **not** mean inference is running.

Example shape:

```json
{
  "status": "ok",
  "initialized": true,
  "ready": true,
  "worker_state": "running",
  "startup_replay_complete": true,
  "detectors": ["ddos", "c2", "dga", "dns_tunnelling", "malware_tls", "recon"]
}
```

**Frontend behavior:**

| Condition | UI state |
|---|---|
| `ready: true` | "System Online / Monitoring Active" |
| `ready: false` | "Backend Starting / Not Ready" |
| request fails | "Backend Offline / Connection Lost" |

Do not treat `HTTP 200` as equivalent to "inference running." Use the readiness fields.

---

## 4. `GET /stats`

Runtime/streaming metrics for dashboard cards.

Backend tracks (not exhaustive):

```
events_received
events_processed
detector_failures
malformed_events
abandoned_events
dropped_events
queue_depth
throughput
inference_latency
end_to_end_latency
```

Example display cards: Events Processed, Alerts, Queue Depth, Detector Errors, Throughput (events/sec), Avg Inference Latency, Avg End-to-End Latency.

**Always render the live values from `/stats`** — never hardcode example numbers.

---

## 5. `GET /alerts`

Returns stored, standardized alerts. Used for the main alert table/feed.

Example row rendering:

```
TIME       THREAT            CONFIDENCE   SEVERITY
12:41:02   DGA_DOMAIN        99.96%       CRITICAL
12:41:01   MALWARE_TLS       77.10%       HIGH
12:40:58   DDoS              37.21%       MEDIUM
12:40:55   C2_BEACONING      43.74%       HIGH
```

---

## 6. Alert object schema

Conceptual fields (map to actual serialized JSON field names — inspect the real response):

```
timestamp
flow_identifier      <-- NOT "flow_id" — schema uses flow_identifier
threat_classification
confidence
severity
evidence
```

`flow_identifier` example display: `192.168.1.10 → 10.0.0.5` (if present in evidence/identifier).

---

## 7. Threat classes

Demo-proven currently:

```
DDoS
BOTNET_C2_BEACONING
DGA_DOMAIN
MALWARE_TLS
```

Also integrated in backend:

```
RECON_PORT_SCAN
DNS_TUNNELLING
```

Data Exfiltration is **currently disabled/unavailable** in the runtime — do not expect or block on it.

**Rule: do not hardcode the UI to a fixed set of threat classes.** Render whatever `threat_class` string the backend sends, with a sensible default/fallback style for classes not explicitly styled — so a newly enabled detector doesn't require a UI rewrite.

---

## 8. Severity

Values: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`.

Frontend maps these to visual treatment (color/icon) only. **Backend decides severity — frontend never calculates it.**

---

## 9. Confidence

Numeric, e.g. `"confidence": 0.9996`.

- Display as a formatted percentage (e.g. `99.96%`).
- Keep the raw numeric value internally.
- Never send a formatted string (`"99.96%"`) back to the backend, and never recompute/modify confidence.

---

## 10. Evidence

Detector-specific — **do not assume a fixed evidence shape across alerts.**

Examples:
- DDoS: `packet rate, byte rate, unique sources, source entropy, syn ratio`
- DGA: domain/query information
- C2: `duration, inter-arrival behavior`
- Malware TLS: `probability, feature count, decision stability, review reasons`

Treat `evidence` as a generic object and render its key/value pairs dynamically. Do not build a fixed-field evidence panel.

---

## 11. `GET /alerts/{id}`

Fetched when a user clicks an alert row, for the detail panel.

Flow: Alert table → click row → `GET /alerts/{id}` → detail panel.

If `404`: show "Alert not found." — this is a normal, handled state, not a crash condition.

---

## 12. WebSocket `/ws`

Makes the dashboard live. New alerts arrive here instead of the frontend polling `/alerts` repeatedly.

**On connect:** show "Live stream connected."
**On incoming message:** parse JSON → validate expected alert fields → prepend to live alert list → update counters/charts.
**On disconnect:** show "Live stream disconnected," then reconnect (retry/backoff strategy is frontend's choice) — never crash.

---

## 13. Combined REST + WebSocket lifecycle (required)

WebSocket alone is **not sufficient** — it only delivers alerts that occur *after* connection. Historical/already-stored alerts must come from REST first.

```
Page loads
   -> GET /health
   -> GET /stats
   -> GET /alerts        (loads existing history)
   -> connect WS /ws     (live updates from here on)
```

---

## 14. Suggested dashboard layout (reference only — visual design is frontend's call)

```
┌───────────────────────────────────────────────────────────┐
│  SPECTRA MONITOR      ● System Online          Live ●      │
├───────────────────────────────────────────────────────────┤
│  Events Processed   Alerts   Throughput   Queue Depth       │
│        15             8        7.27/s        0              │
├───────────────────────────────────────────────────────────┤
│  THREAT SUMMARY                                             │
│  DDoS         █ 1     C2 Beaconing  █ 1                     │
│  DGA          ██ 2    Malware TLS   ████ 4                  │
├───────────────────────────────────────────────────────────┤
│  LIVE ALERTS                                                 │
│  Time     Threat          Confidence   Severity              │
│  12:41    DGA_DOMAIN      99.96%       CRITICAL              │
│  12:40    MALWARE_TLS     77.10%       HIGH                  │
└───────────────────────────────────────────────────────────┘
```

---

## 15. What the frontend must NOT do

- ❌ Never call ML models or load `.pkl`/model files directly from frontend.
- ❌ Never duplicate backend detection logic (no `if packets > X: DDoS` style logic in the UI).
- ❌ Never calculate confidence.
- ❌ Never calculate severity.
- ❌ Never modify evidence — display only.
- ❌ Never assume model internals (XGBoost vs Random Forest vs SVM — irrelevant).
- ❌ Never hardcode today's alert counts — everything is dynamic.
- ❌ Never assume every detector produces the same evidence shape.
- ❌ Never hardcode the UI to only the currently-demoed threat classes.

---

## 16. Responsibility boundary

**Backend owns:** ingestion, normalization, feature prep, windowing, model inference, detector routing, confidence, severity, evidence, alert creation/persistence, streaming, metrics, readiness.

**Frontend owns:** dashboard layout, charts, tables, alert cards, filtering, alert detail view, visual severity treatment, live feed presentation, connection status, user interaction.

**Shared contract:** REST JSON + WebSocket JSON, as defined above.

---

## 17. Required frontend error/edge-case handling

- Backend unavailable
- Backend not ready (`ready: false`)
- WebSocket disconnect / reconnect
- Empty alert list
- `404` on `/alerts/{id}`
- Dynamic/unknown evidence keys
- Dynamically changing alert counts and previously-unseen threat classes
