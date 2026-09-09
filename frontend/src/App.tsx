import React, { useEffect, useState } from 'react';
import { useSpectraStore } from './store/useSpectraStore';
import { useWebSocket } from './hooks/useWebSocket';
import { TopBar } from './components/TopBar';
import { StatsRow } from './components/StatsRow';
import { PacketFlowVisual } from './components/PacketFlowVisual';
import { ThreatSummaryChart } from './components/ThreatSummaryChart';
import { LiveAlertTable } from './components/LiveAlertTable';
import { AlertDetailPanel } from './components/AlertDetailPanel';
import { MockTestPanel } from './components/MockTestPanel';
import { API_CONFIG } from './services/api';
import { AlertTriangle, WifiOff, RefreshCw } from 'lucide-react';

export const App: React.FC = () => {
  const fetchInitialData = useSpectraStore((s) => s.fetchInitialData);
  const fetchStats = useSpectraStore((s) => s.fetchStats);
  const health = useSpectraStore((s) => s.health);
  const systemError = useSpectraStore((s) => s.systemError);

  const [showTestPanel, setShowTestPanel] = useState(false);

  /**
   * REQUIRED DATA LIFECYCLE ORDER:
   * 1. Page loads -> GET /health
   * 2. GET /stats
   * 3. GET /alerts (loads existing history)
   * 4. Open WebSocket connection for live updates from that point forward
   */
  useEffect(() => {
    fetchInitialData();

    // Periodically refresh /stats every 4 seconds to maintain live metrics
    const statsInterval = setInterval(() => {
      fetchStats();
    }, 4000);

    return () => clearInterval(statsInterval);
  }, [fetchInitialData, fetchStats]);

  // Connect native/mock WebSocket stream
  useWebSocket();

  return (
    <div className="min-h-screen bg-background text-gray-100 flex flex-col font-sans">
      {/* Top Navigation Bar */}
      <TopBar
        onToggleTestPanel={() => setShowTestPanel(!showTestPanel)}
        showTestPanel={showTestPanel}
      />

      {/* Main Dashboard Canvas */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 py-6">
        {/* Mock Edge-Case Test Harness */}
        {API_CONFIG.USE_MOCK_DATA && API_CONFIG.IS_DEVELOPMENT && showTestPanel && (
          <MockTestPanel onClose={() => setShowTestPanel(false)} />
        )}

        {/* System Error / Offline Alert Banner */}
        {systemError && (
          <div className="bg-red-950/50 border border-red-500/40 rounded-xl p-4 mb-6 flex items-center justify-between shadow-lg">
            <div className="flex items-center space-x-3">
              <WifiOff className="w-5 h-5 text-red-400 shrink-0" />
              <div>
                <h3 className="font-mono text-xs font-bold text-red-300 uppercase">
                  Backend Service Unavailable
                </h3>
                <p className="text-xs text-red-200/80 font-mono mt-0.5">{systemError}</p>
              </div>
            </div>
            <button
              onClick={() => fetchInitialData()}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-red-900/60 hover:bg-red-900 border border-red-500/50 text-xs font-mono text-white transition-colors"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Retry Connection</span>
            </button>
          </div>
        )}

        {/* Backend Not Ready Banner */}
        {health && !health.ready && !systemError && (
          <div className="bg-amber-950/50 border border-amber-500/40 rounded-xl p-4 mb-6 flex items-center space-x-3 shadow-lg">
            <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 animate-bounce" />
            <div>
              <h3 className="font-mono text-xs font-bold text-amber-300 uppercase">
                Backend Initializing / Worker Replay In Progress
              </h3>
              <p className="text-xs text-amber-200/80 font-mono mt-0.5">
                Status: {health.status} | Worker State: {health.worker_state} | Startup Replay Complete:{' '}
                {health.startup_replay_complete ? 'YES' : 'NO'}
              </p>
            </div>
          </div>
        )}

        {/* 1. Live Stats Cards Row */}
        <StatsRow />

        {/* 2. Packet Flow & Diode Visual Strip */}
        <PacketFlowVisual />

        {/* 3. Dynamic Threat Summary Bar Chart */}
        <ThreatSummaryChart />

        {/* 4. Live Alert Feed Table */}
        <LiveAlertTable />
      </main>

      {/* 5. Alert Detail Slide-Over Panel */}
      <AlertDetailPanel />

      {/* Footer */}
      <footer className="border-t border-surface-border bg-surface py-4 text-center text-xs font-mono text-gray-400">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>SPECTRA Monitoring Engine — Integration Contract Compliance v1.0</span>
          <span>Security Operations Center Telemetry</span>
        </div>
      </footer>
    </div>
  );
};
