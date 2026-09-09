import React from 'react';
import { useSpectraStore } from '../store/useSpectraStore';
import { API_CONFIG } from '../services/api';
import { Shield, Wifi, RefreshCw, Wrench } from 'lucide-react';

interface TopBarProps {
  onToggleTestPanel: () => void;
  showTestPanel: boolean;
}

export const TopBar: React.FC<TopBarProps> = ({ onToggleTestPanel, showTestPanel }) => {
  const health = useSpectraStore((s) => s.health);
  const systemError = useSpectraStore((s) => s.systemError);
  const isSystemLoading = useSpectraStore((s) => s.isSystemLoading);
  const connectionStatus = useSpectraStore((s) => s.connectionStatus);
  const fetchInitialData = useSpectraStore((s) => s.fetchInitialData);

  // Readiness derived specifically from GET /health's `ready` boolean field
  let statusState: 'online' | 'not-ready' | 'offline' = 'offline';
  let statusText = 'Backend Offline';
  let statusDetail = 'Connection Lost';

  if (systemError || !health) {
    statusState = 'offline';
    statusText = 'Backend Offline';
    statusDetail = systemError || 'Unable to connect';
  } else if (health.ready) {
    statusState = 'online';
    statusText = 'System Online';
    statusDetail = `Monitoring Active (${health.detectors?.length || 0} detectors)`;
  } else {
    statusState = 'not-ready';
    statusText = 'Backend Starting';
    statusDetail = `Worker State: ${health.worker_state || 'initializing'}`;
  }

  // Live WS status
  const isWsLive = connectionStatus === 'connected';

  return (
    <header className="bg-surface border-b border-surface-border px-4 py-3 sticky top-0 z-30 shadow-lg backdrop-blur-md bg-opacity-95">
      <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3">
        {/* Left Branding */}
        <div className="flex items-center space-x-3">
          <div className="relative">
            <div className="w-9 h-9 rounded-lg bg-cyan-950/60 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-[0_0_15px_rgba(0,240,255,0.2)]">
              <Shield className="w-5 h-5" />
            </div>
            <div className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-cyan-400 animate-ping" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="font-mono text-lg font-bold tracking-wider text-gray-100 uppercase">
                SPECTRA<span className="text-cyan-400">_SOC</span>
              </h1>
              {API_CONFIG.USE_MOCK_DATA && (
                <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-purple-950/60 text-purple-300 border border-purple-500/30">
                  Mock Mode
                </span>
              )}
              <span
                title="Observes mirrored telemetry only; does not actively probe, block, or modify production traffic."
                className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-cyan-950/60 text-cyan-300 border border-cyan-500/30"
              >
                Passive / Read-Only
              </span>
            </div>
            <p className="text-xs text-gray-400 hidden sm:block">
              Real-Time Network Threat Detection &amp; Packet Flow Analyzer
            </p>
          </div>
        </div>

        {/* Right Status Indicators & Controls */}
        <div className="flex items-center space-x-3 flex-wrap justify-end">
          {/* Health Readiness Card */}
          <div className="flex items-center space-x-2.5 px-3 py-1.5 rounded-lg bg-surface-card border border-surface-border">
            <span className="relative flex h-2.5 w-2.5">
              {statusState === 'online' && (
                <>
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
                </>
              )}
              {statusState === 'not-ready' && (
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-amber-400"></span>
              )}
              {statusState === 'offline' && (
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-red-500"></span>
              )}
            </span>
            <div className="text-left">
              <div className="flex items-center space-x-1">
                <span className="text-xs font-semibold text-gray-200">{statusText}</span>
              </div>
              <p className="text-[10px] text-gray-400 font-mono truncate max-w-[150px]">
                {statusDetail}
              </p>
            </div>
          </div>

          {/* WebSocket Live Stream Status */}
          <div
            className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg border text-xs font-mono transition-colors ${
              isWsLive
                ? 'bg-emerald-950/40 text-emerald-400 border-emerald-500/30'
                : connectionStatus === 'connecting'
                ? 'bg-amber-950/40 text-amber-300 border-amber-500/30'
                : 'bg-red-950/40 text-red-400 border-red-500/30'
            }`}
          >
            <Wifi className={`w-3.5 h-3.5 ${isWsLive ? 'animate-pulse' : ''}`} />
            <span>
              Live {isWsLive ? '●' : connectionStatus === 'connecting' ? '⌛' : '○'}
            </span>
          </div>

          {/* Reload / Refresh Button */}
          <button
            onClick={() => fetchInitialData()}
            disabled={isSystemLoading}
            title="Refresh system state"
            className="p-2 rounded-lg bg-surface-card hover:bg-surface-hover border border-surface-border text-gray-300 hover:text-white transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${isSystemLoading ? 'animate-spin text-cyan-400' : ''}`} />
          </button>

          {/* Test Controls Toggle Button */}
          {API_CONFIG.USE_MOCK_DATA && API_CONFIG.IS_DEVELOPMENT && (
            <button
              onClick={onToggleTestPanel}
              className={`flex items-center space-x-1.5 px-2.5 py-1.5 rounded-lg border text-xs font-mono transition-colors ${
                showTestPanel
                  ? 'bg-cyan-950/70 text-cyan-300 border-cyan-500/50'
                  : 'bg-surface-card hover:bg-surface-hover text-gray-300 border-surface-border'
              }`}
              title="Toggle mock testing & error simulation toolbar"
            >
              <Wrench className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Test Scenarios</span>
            </button>
          )}
        </div>
      </div>
    </header>
  );
};
