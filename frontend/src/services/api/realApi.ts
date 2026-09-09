import { Alert, DataProviderInterface, HealthResponse, StatsResponse, WebSocketLike } from '../../types';
import { API_CONFIG } from './config';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

export function normalizeBackendAlert(payload: unknown): Alert | null {
  if (!isRecord(payload)) return null;

  if (typeof payload.id === 'string' && typeof payload.threat_classification === 'string') {
    return payload as unknown as Alert;
  }

  const flow = payload.flow_identifier;
  const classification = payload.threat_classification;
  const scoring = payload.scoring;
  if (
    typeof payload.alert_id !== 'string' ||
    typeof payload.timestamp !== 'string' ||
    !isRecord(flow) ||
    typeof flow.src_ip !== 'string' ||
    typeof flow.dst_ip !== 'string' ||
    typeof flow.src_port !== 'number' ||
    typeof flow.dst_port !== 'number' ||
    typeof flow.protocol !== 'string' ||
    !isRecord(classification) ||
    typeof classification.threat_class !== 'string' ||
    !isRecord(scoring) ||
    typeof scoring.confidence_score !== 'number' ||
    typeof scoring.severity !== 'string' ||
    !isRecord(payload.supporting_evidence)
  ) {
    return null;
  }

  return {
    id: payload.alert_id,
    timestamp: payload.timestamp,
    flow_identifier: `${flow.src_ip}:${flow.src_port} -> ${flow.dst_ip}:${flow.dst_port} (${flow.protocol})`,
    threat_classification: classification.threat_class,
    confidence: scoring.confidence_score,
    severity: scoring.severity,
    evidence: payload.supporting_evidence,
  };
}

function normalizeAlerts(payload: unknown): Alert[] {
  if (!Array.isArray(payload)) {
    throw new Error('Backend returned an invalid alerts response');
  }

  const alerts = payload.map(normalizeBackendAlert);
  if (alerts.some((alert) => alert === null)) {
    throw new Error('Backend returned a malformed alert payload');
  }
  return alerts as Alert[];
}

/**
 * Real API Implementation for SPECTRA Backend
 * 
 * Uses native fetch() and WebSocket against the FastAPI backend defined in API_CONFIG.
 */
export class RealDataProvider implements DataProviderInterface {
  private baseUrl: string;
  private wsUrl: string;

  constructor() {
    this.baseUrl = API_CONFIG.HTTP_BASE_URL;
    this.wsUrl = API_CONFIG.WS_BASE_URL;
  }

  async getHealth(): Promise<HealthResponse> {
    const res = await fetch(`${this.baseUrl}/health`);
    if (!res.ok) {
      throw new Error(`HTTP error! status: ${res.status}`);
    }
    return res.json();
  }

  async getStats(): Promise<StatsResponse> {
    const res = await fetch(`${this.baseUrl}/stats`);
    if (!res.ok) {
      throw new Error(`HTTP error! status: ${res.status}`);
    }
    const payload = await res.json();
    if (!isRecord(payload)) throw new Error('Backend returned an invalid stats response');

    const inferenceLatency = isRecord(payload.inference_latency) ? payload.inference_latency : {};
    const endToEndLatency = isRecord(payload.end_to_end_latency) ? payload.end_to_end_latency : {};
    return {
      events_received: Number(payload.events_received) || 0,
      events_processed: Number(payload.events_processed) || 0,
      alerts_generated: Number(payload.alerts_generated) || 0,
      detector_failures: Number(payload.detector_failures) || 0,
      malformed_events: Number(payload.malformed_events) || 0,
      abandoned_events: Number(payload.abandoned_events) || 0,
      dropped_events: Number(payload.dropped_events) || 0,
      queue_depth: Number(payload.queue_depth) || 0,
      throughput: Number(payload.throughput_events_per_sec) || 0,
      inference_latency: (Number(inferenceLatency.latest_seconds) || 0) * 1000,
      end_to_end_latency: (Number(endToEndLatency.latest_seconds) || 0) * 1000,
    };
  }

  async getAlerts(): Promise<Alert[]> {
    const res = await fetch(`${this.baseUrl}/alerts`);
    if (!res.ok) {
      throw new Error(`HTTP error! status: ${res.status}`);
    }
    return normalizeAlerts(await res.json());
  }

  async getAlertById(id: string): Promise<Alert | null> {
    const res = await fetch(`${this.baseUrl}/alerts/${encodeURIComponent(id)}`);
    if (res.status === 404) {
      return null; // Handled 404: alert not found
    }
    if (!res.ok) {
      throw new Error(`HTTP error! status: ${res.status}`);
    }
    const alert = normalizeBackendAlert(await res.json());
    if (!alert) throw new Error('Backend returned a malformed alert payload');
    return alert;
  }

  createWebSocketConnection(urlSuffix = '/ws'): WebSocketLike {
    const fullWsUrl = `${this.wsUrl}${urlSuffix}`;
    const ws = new WebSocket(fullWsUrl);
    return ws as unknown as WebSocketLike;
  }
}
