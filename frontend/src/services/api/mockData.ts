import { Alert, HealthResponse, StatsResponse, WebSocketLike } from '../../types';
import { API_CONFIG } from './config';

/**
 * Initial Mock Fixture Alerts
 * Includes sample alerts across diverse threat classes (including RECON_PORT_SCAN and DNS_TUNNELLING)
 * to ensure the UI is not hardcoded to only 4 demo threat classes.
 */
let MOCK_ALERTS: Alert[] = [
  {
    id: 'alt_001',
    timestamp: new Date(Date.now() - 30 * 1000).toISOString(),
    flow_identifier: '192.168.1.105:49822 → 198.51.100.42:443',
    threat_classification: 'DGA_DOMAIN',
    confidence: 0.9996,
    severity: 'CRITICAL',
    evidence: {
      queried_domain: 'x89a-z09f-kw91-mlq.biz',
      domain_entropy: 4.88,
      n_gram_score: 0.082,
      dns_query_type: 'TXT',
      resolved_ips: ['192.0.2.1', '192.0.2.2'],
      ttl: 60,
    },
  },
  {
    id: 'alt_002',
    timestamp: new Date(Date.now() - 60 * 1000).toISOString(),
    flow_identifier: '10.0.4.12:53210 → 172.16.0.88:8443',
    threat_classification: 'MALWARE_TLS',
    confidence: 0.8710,
    severity: 'HIGH',
    evidence: {
      ja3_hash: '771ac37153401c00a9e94d3e3a420a2e',
      cipher_suite: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
      cert_issuer: 'Unknown CA / Self-Signed',
      decision_stability: 0.98,
      review_reasons: [
        'Self-signed intermediate certificate',
        'Abnormal TLS extension order matching malware signature',
      ],
    },
  },
  {
    id: 'alt_003',
    timestamp: new Date(Date.now() - 120 * 1000).toISOString(),
    flow_identifier: '192.168.1.200:80 → MULTIPLE_TARGETS',
    threat_classification: 'DDoS',
    confidence: 0.6721,
    severity: 'MEDIUM',
    evidence: {
      packet_rate_pps: 15420,
      byte_rate_bps: 12450000,
      unique_sources: 840,
      source_entropy: 7.82,
      syn_ratio: 0.94,
      window_duration_sec: 10,
    },
  },
  {
    id: 'alt_004',
    timestamp: new Date(Date.now() - 180 * 1000).toISOString(),
    flow_identifier: '10.0.1.15:44321 → 203.0.113.99:9001',
    threat_classification: 'BOTNET_C2_BEACONING',
    confidence: 0.9374,
    severity: 'HIGH',
    evidence: {
      beacon_interval_sec: 30.0,
      jitter_stddev: 0.12,
      c2_endpoint: 'command-control-node.net',
      bytes_out: 4820,
      bytes_in: 512,
      connection_count_1h: 144,
    },
  },
  {
    id: 'alt_005',
    timestamp: new Date(Date.now() - 240 * 1000).toISOString(),
    flow_identifier: '192.168.1.50 → 192.168.1.0/24',
    threat_classification: 'RECON_PORT_SCAN',
    confidence: 0.9540,
    severity: 'MEDIUM',
    evidence: {
      ports_scanned_count: 1024,
      port_range: '1-1024',
      scan_rate_ports_per_sec: 450,
      scan_technique: 'SYN Stealth Scan',
      open_ports_discovered: [22, 80, 443, 8080],
    },
  },
  {
    id: 'alt_006',
    timestamp: new Date(Date.now() - 300 * 1000).toISOString(),
    flow_identifier: '10.0.2.14:53 → 8.8.8.8:53',
    threat_classification: 'DNS_TUNNELLING',
    confidence: 0.9880,
    severity: 'CRITICAL',
    evidence: {
      query_length_max: 210,
      txt_record_ratio: 0.88,
      payload_entropy: 5.92,
      total_bytes_exfiltrated_kb: 450.5,
      subdomain_depth: 4,
    },
  },
];

let mockAlertCounter = 7;

export function generateNewMockAlert(): Alert {
  const threatTypes: Array<{
    threat: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    minConf: number;
    maxConf: number;
    evidenceGen: () => Record<string, any>;
  }> = [
    {
      threat: 'DGA_DOMAIN',
      severity: 'CRITICAL',
      minConf: 0.92,
      maxConf: 0.999,
      evidenceGen: () => ({
        queried_domain: `sub-${Math.random().toString(36).substring(2, 8)}.evil-dga.org`,
        domain_entropy: +(3.5 + Math.random() * 2).toFixed(2),
        n_gram_score: +(Math.random() * 0.1).toFixed(3),
        dns_query_type: 'A',
        ttl: 30,
      }),
    },
    {
      threat: 'MALWARE_TLS',
      severity: 'HIGH',
      minConf: 0.80,
      maxConf: 0.96,
      evidenceGen: () => ({
        ja3_hash: Math.random().toString(16).substring(2, 18),
        cipher_suite: 'TLS_AES_256_GCM_SHA384',
        cert_issuer: 'Untrusted Self-Signed Authority',
        decision_stability: +(0.9 + Math.random() * 0.09).toFixed(2),
      }),
    },
    {
      threat: 'DDoS',
      severity: 'HIGH',
      minConf: 0.75,
      maxConf: 0.98,
      evidenceGen: () => ({
        packet_rate_pps: Math.floor(10000 + Math.random() * 50000),
        byte_rate_bps: Math.floor(5000000 + Math.random() * 20000000),
        unique_sources: Math.floor(500 + Math.random() * 2000),
        syn_ratio: +(0.8 + Math.random() * 0.19).toFixed(2),
      }),
    },
    {
      threat: 'BOTNET_C2_BEACONING',
      severity: 'HIGH',
      minConf: 0.85,
      maxConf: 0.97,
      evidenceGen: () => ({
        beacon_interval_sec: 15.0,
        jitter_stddev: +(Math.random() * 0.05).toFixed(3),
        c2_endpoint: `c2-${Math.floor(Math.random() * 100)}.malicious.io`,
        bytes_out: Math.floor(1000 + Math.random() * 5000),
      }),
    },
    {
      threat: 'RECON_PORT_SCAN',
      severity: 'LOW',
      minConf: 0.70,
      maxConf: 0.90,
      evidenceGen: () => ({
        ports_scanned_count: Math.floor(100 + Math.random() * 500),
        port_range: '20-1024',
        scan_rate_ports_per_sec: Math.floor(200 + Math.random() * 300),
      }),
    },
    {
      threat: 'DNS_TUNNELLING',
      severity: 'CRITICAL',
      minConf: 0.94,
      maxConf: 0.995,
      evidenceGen: () => ({
        query_length_max: Math.floor(180 + Math.random() * 50),
        txt_record_ratio: +(0.7 + Math.random() * 0.25).toFixed(2),
        total_bytes_exfiltrated_kb: +(100 + Math.random() * 800).toFixed(1),
      }),
    },
  ];

  const template = threatTypes[Math.floor(Math.random() * threatTypes.length)];
  const srcIp = `192.168.1.${Math.floor(2 + Math.random() * 200)}`;
  const dstIp = `10.0.0.${Math.floor(2 + Math.random() * 50)}`;
  const srcPort = Math.floor(30000 + Math.random() * 30000);
  const dstPort = [80, 443, 53, 8080, 8443][Math.floor(Math.random() * 5)];

  const id = `alt_${String(mockAlertCounter++).padStart(3, '0')}`;
  const confidence = +(template.minConf + Math.random() * (template.maxConf - template.minConf)).toFixed(4);

  const newAlert: Alert = {
    id,
    timestamp: new Date().toISOString(),
    flow_identifier: `${srcIp}:${srcPort} → ${dstIp}:${dstPort}`,
    threat_classification: template.threat,
    confidence,
    severity: template.severity,
    evidence: template.evidenceGen(),
  };

  // Add to internal list so getAlertById works for newly emitted alerts
  MOCK_ALERTS.unshift(newAlert);
  return newAlert;
}

export function getMockHealth(): HealthResponse {
  return {
    status: 'ok',
    initialized: true,
    ready: true,
    worker_state: 'running',
    startup_replay_complete: true,
    detectors: ['ddos', 'c2', 'dga', 'dns_tunnelling', 'malware_tls', 'recon'],
  };
}

export function getMockStats(): StatsResponse {
  return {
    events_received: 145890 + Math.floor(Math.random() * 50),
    events_processed: 145885 + Math.floor(Math.random() * 50),
    alerts_generated: MOCK_ALERTS.length,
    detector_failures: 0,
    malformed_events: 0,
    abandoned_events: 0,
    dropped_events: 0,
    queue_depth: Math.floor(Math.random() * 3),
    throughput: +(12.5 + Math.random() * 4.5).toFixed(2), // ~12-17 events/sec
    inference_latency: +(1.1 + Math.random() * 0.6).toFixed(2), // ms
    end_to_end_latency: +(4.2 + Math.random() * 1.8).toFixed(2), // ms
  };
}

export function getMockAlerts(): Alert[] {
  return [...MOCK_ALERTS];
}

export function getMockAlertById(id: string): Alert | null {
  const alert = MOCK_ALERTS.find((a) => a.id === id);
  return alert ? { ...alert } : null;
}

/**
 * Mock WebSocket Emitter
 * Simulates a native WebSocket connection for development/demo when backend is offline.
 */
export class MockWebSocketEmitter implements WebSocketLike {
  public onopen: ((event: any) => void) | null = null;
  public onmessage: ((event: { data: string }) => void) | null = null;
  public onerror: ((event: any) => void) | null = null;
  public onclose: ((event: any) => void) | null = null;

  private timer: any = null;
  private isClosed = false;

  constructor() {
    // Simulate connection establishment delay
    setTimeout(() => {
      if (!this.isClosed && this.onopen) {
        this.onopen({ type: 'open' });
        this.startStreaming();
      }
    }, 150);
  }

  private startStreaming() {
    this.timer = setInterval(() => {
      if (!this.isClosed && this.onmessage) {
        const alert = generateNewMockAlert();
        // Backend WebSocket emits alert JSON object
        this.onmessage({ data: JSON.stringify(alert) });
      }
    }, API_CONFIG.MOCK_EMIT_INTERVAL_MS);
  }

  public close(): void {
    this.isClosed = true;
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    if (this.onclose) {
      this.onclose({ type: 'close', wasClean: true, code: 1000, reason: 'Mock closed' });
    }
  }

  public send(data: string): void {
    console.log('[MockWS] Received message from client:', data);
  }
}
