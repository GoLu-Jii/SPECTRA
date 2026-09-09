/**
 * =================================================================================
 * SPECTRA FRONTEND — DATA LAYER MODULE & INTEGRATION GUIDE
 * =================================================================================
 * 
 * INSTRUCTIONS FOR CONNECTING TO THE REAL BACKEND:
 * 
 * 1. VERIFY BACKEND ENDPOINTS:
 *    Before switching off mock mode, verify the running FastAPI backend using curl:
 *      curl http://localhost:8000/health
 *      curl http://localhost:8000/stats
 *      curl http://localhost:8000/alerts
 *    Ensure endpoints return valid JSON matching SPECTRA_Frontend_Integration_Contract.md.
 * 
 * 2. FLIP THE CONFIG SWITCH:
 *    Open `./config.ts` and set `USE_MOCK_DATA: false`.
 *    Optionally update `HTTP_BASE_URL` and `WS_BASE_URL` if your backend is hosted elsewhere.
 * 
 * 3. FIELD NAME VERIFICATION CHECKLIST:
 *    - Alert identifier: `flow_identifier` (NOT `flow_id`)
 *    - Health readiness: `ready` (boolean flag determines system operational status)
 *    - Alert confidence: numeric e.g. 0.9996 (frontend formats it as percentage)
 *    - Evidence: dynamic key-value object (rendered generically)
 * 
 * =================================================================================
 */

import { Alert, DataProviderInterface, HealthResponse, StatsResponse, WebSocketLike } from '../../types';
import { API_CONFIG } from './config';
import {
  getMockAlertById,
  getMockAlerts,
  getMockHealth,
  getMockStats,
  MockWebSocketEmitter,
} from './mockData';
import { RealDataProvider } from './realApi';

// Simulated state flags for manual UI edge-case testing
let simulateOfflineMode = false;
let simulateNotReadyMode = false;
let simulateEmptyAlertsMode = false;

export function setSimulatedOffline(offline: boolean) {
  simulateOfflineMode = offline;
}

export function getSimulatedOffline(): boolean {
  return simulateOfflineMode;
}

export function setSimulatedNotReady(notReady: boolean) {
  simulateNotReadyMode = notReady;
}

export function getSimulatedNotReady(): boolean {
  return simulateNotReadyMode;
}

export function setSimulatedEmptyAlerts(empty: boolean) {
  simulateEmptyAlertsMode = empty;
}

export function getSimulatedEmptyAlerts(): boolean {
  return simulateEmptyAlertsMode;
}

/**
 * Mock Data Provider implementing DataProviderInterface
 */
class MockDataProvider implements DataProviderInterface {
  async getHealth(): Promise<HealthResponse> {
    await this.delay(API_CONFIG.MOCK_NETWORK_LATENCY_MS);
    
    if (simulateOfflineMode) {
      throw new Error('Simulated Backend Offline');
    }
    
    const health = getMockHealth();
    if (simulateNotReadyMode) {
      return { ...health, ready: false, worker_state: 'starting' };
    }
    
    return health;
  }

  async getStats(): Promise<StatsResponse> {
    await this.delay(API_CONFIG.MOCK_NETWORK_LATENCY_MS);
    
    if (simulateOfflineMode) {
      throw new Error('Simulated Backend Offline');
    }
    
    return getMockStats();
  }

  async getAlerts(): Promise<Alert[]> {
    await this.delay(API_CONFIG.MOCK_NETWORK_LATENCY_MS);
    
    if (simulateOfflineMode) {
      throw new Error('Simulated Backend Offline');
    }
    
    if (simulateEmptyAlertsMode) {
      return [];
    }
    
    return getMockAlerts();
  }

  async getAlertById(id: string): Promise<Alert | null> {
    await this.delay(API_CONFIG.MOCK_NETWORK_LATENCY_MS);
    
    if (simulateOfflineMode) {
      throw new Error('Simulated Backend Offline');
    }
    
    return getMockAlertById(id);
  }

  createWebSocketConnection(_urlSuffix?: string): WebSocketLike {
    if (simulateOfflineMode) {
      // Return a closed mock socket to simulate offline
      const mock = new MockWebSocketEmitter();
      setTimeout(() => mock.close(), 50);
      return mock;
    }
    return new MockWebSocketEmitter();
  }

  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

// Singleton instances
const mockProvider = new MockDataProvider();
const realProvider = new RealDataProvider();

/**
 * Active Data Provider exported to the rest of the application.
 * Components NEVER call fetch() or new WebSocket() directly — they interact solely through this layer.
 */
export const dataProvider: DataProviderInterface = {
  getHealth: () => (API_CONFIG.USE_MOCK_DATA ? mockProvider.getHealth() : realProvider.getHealth()),
  getStats: () => (API_CONFIG.USE_MOCK_DATA ? mockProvider.getStats() : realProvider.getStats()),
  getAlerts: () => (API_CONFIG.USE_MOCK_DATA ? mockProvider.getAlerts() : realProvider.getAlerts()),
  getAlertById: (id: string) => (API_CONFIG.USE_MOCK_DATA ? mockProvider.getAlertById(id) : realProvider.getAlertById(id)),
  createWebSocketConnection: (urlSuffix) =>
    API_CONFIG.USE_MOCK_DATA
      ? mockProvider.createWebSocketConnection(urlSuffix)
      : realProvider.createWebSocketConnection(urlSuffix),
};

export { API_CONFIG };
