/**
 * SPECTRA Integration Types
 * Based on SPECTRA_Frontend_Integration_Contract.md
 */

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | string;

export interface HealthResponse {
  status: string;
  initialized: boolean;
  ready: boolean;
  worker_state: string;
  startup_replay_complete: boolean;
  detectors: string[];
}

export interface StatsResponse {
  events_received: number;
  events_processed: number;
  alerts_generated: number;
  detector_failures: number;
  malformed_events: number;
  abandoned_events: number;
  dropped_events: number;
  queue_depth: number;
  throughput: number; // events/sec
  inference_latency: number; // ms
  end_to_end_latency: number; // ms
  [key: string]: number; // Allow future dynamic stat fields
}

export interface Alert {
  id: string;
  timestamp: string;
  flow_identifier: string; // CRITICAL: contract specifies flow_identifier, not flow_id
  threat_classification: string;
  confidence: number; // e.g. 0.9996 (display as percentage in UI)
  severity: SeverityLevel;
  evidence: Record<string, any>; // Dynamic key-value dictionary per detector
}

export interface WebSocketAlertMessage {
  type?: string;
  data?: Alert;
  [key: string]: any;
}

export type ConnectionStatus = 'connected' | 'connecting' | 'disconnected' | 'error';

export interface DataProviderInterface {
  getHealth(): Promise<HealthResponse>;
  getStats(): Promise<StatsResponse>;
  getAlerts(): Promise<Alert[]>;
  getAlertById(id: string): Promise<Alert | null>;
  createWebSocketConnection(urlSuffix?: string): WebSocketLike;
}

export interface WebSocketLike {
  onopen: ((event: any) => void) | null;
  onmessage: ((event: { data: string }) => void) | null;
  onerror: ((event: any) => void) | null;
  onclose: ((event: any) => void) | null;
  close(): void;
  send?(data: string): void;
}
