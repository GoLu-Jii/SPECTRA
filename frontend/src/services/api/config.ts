/**
 * SPECTRA Data Layer Configuration
 * 
 * Set USE_MOCK_DATA to `false` when connecting to a real running backend.
 * Set BASE_URL to your backend host (e.g. http://localhost:8000).
 */

const frontendEnv = (import.meta as ImportMeta & {
  env?: Record<string, string | undefined>;
}).env ?? {};

export const API_CONFIG = {
  // Toggle this switch to false to connect to the real FastAPI backend
  USE_MOCK_DATA: false,
  IS_DEVELOPMENT: frontendEnv.MODE === 'development',
  
  // Real backend base URLs
  HTTP_BASE_URL: (frontendEnv.VITE_SPECTRA_API_URL || 'http://localhost:8000').replace(/\/$/, ''),
  WS_BASE_URL: (frontendEnv.VITE_SPECTRA_WS_URL ||
    (frontendEnv.VITE_SPECTRA_API_URL || 'http://localhost:8000').replace(/^http/, 'ws')).replace(/\/$/, ''),

  // Mock settings
  MOCK_EMIT_INTERVAL_MS: 3500, // Interval for mock WebSocket alert stream
  MOCK_NETWORK_LATENCY_MS: 150, // Simulated network latency for REST endpoints
};
