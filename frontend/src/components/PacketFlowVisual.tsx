import React, { useEffect, useRef, useState, useCallback } from 'react';
import { useSpectraStore } from '../store/useSpectraStore';
import { formatConfidence, formatTimestamp, getSeverityBadgeStyle } from '../utils/formatters';
import { Router, ArrowRightLeft, Cpu, LayoutDashboard, AlertCircle, Pause, Play } from 'lucide-react';
import { Alert } from '../types';

interface MovingDot {
  id: string;
  isThreat: boolean;
  alertObj?: Alert;
  durationSec: number;
  flared: boolean;
}

export const PacketFlowVisual: React.FC = () => {
  const stats = useSpectraStore((s) => s.stats);
  const scannedFlows = useSpectraStore((s) => s.totalScannedFlows);
  const flaggedThreats = useSpectraStore((s) => s.totalFlaggedThreats);
  const alerts = useSpectraStore((s) => s.alerts);
  const selectAlert = useSpectraStore((s) => s.selectAlert);
  const incrementScannedFlows = useSpectraStore((s) => s.incrementScannedFlows);

  const [dots, setDots] = useState<MovingDot[]>([]);
  const [isPaused, setIsPaused] = useState(false);
  const [flaredDots, setFlaredDots] = useState<Alert[]>([]);

  const lastAlertIdRef = useRef<string | null>(null);

  /**
   * Ambient Dot Spawn Rate Formula:
   * spawnIntervalMs = 1000 / Math.max(throughput, 1.0)
   * Derived dynamically from `throughput` returned by GET /stats.
   * Higher throughput = faster dot generation across the monitoring diode lane.
   */
  const throughput = stats?.throughput ?? 0;
  const spawnIntervalMs = Math.max(120, Math.min(1000 / Math.max(throughput, 1.0), 1000));

  // Spawn clean background ambient dot
  const spawnDot = useCallback((threatAlert?: Alert) => {
    const dotId = `dot_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`;
    const durationSec = +(2.8 + Math.random() * 0.8).toFixed(2); // ~3 seconds travel duration

    const newDot: MovingDot = {
      id: dotId,
      isThreat: !!threatAlert,
      alertObj: threatAlert,
      durationSec,
      flared: false,
    };

    setDots((prev) => [...prev.slice(-25), newDot]); // Keep active DOM dots low
    incrementScannedFlows(1);

    // Auto cleanup after dot reaches end of visual lane
    setTimeout(() => {
      setDots((prev) => prev.filter((d) => d.id !== dotId));
    }, durationSec * 1000 + 100);
  }, [incrementScannedFlows]);

  // Ambient dot loop based on live throughput
  useEffect(() => {
    if (isPaused || !stats) return;

    const interval = setInterval(() => {
      spawnDot();
    }, spawnIntervalMs);

    return () => clearInterval(interval);
  }, [isPaused, spawnIntervalMs, spawnDot, stats]);

  // Watch for incoming real alerts to trigger red threat flares
  useEffect(() => {
    if (alerts.length === 0) return;
    const newestAlert = alerts[0];

    // Trigger flare only when a genuinely new alert arrives
    if (newestAlert && newestAlert.id !== lastAlertIdRef.current) {
      lastAlertIdRef.current = newestAlert.id;

      // Spawn a red flared threat dot immediately
      spawnDot(newestAlert);

      // Keep recent 4 flared alerts for the visual strip feed
      setFlaredDots((prev) => {
        if (prev.some((a) => a.id === newestAlert.id)) return prev;
        return [newestAlert, ...prev].slice(0, 4);
      });
    }
  }, [alerts, spawnDot]);

  // Populate initial flared dots from existing history if empty
  useEffect(() => {
    if (flaredDots.length === 0 && alerts.length > 0) {
      setFlaredDots(alerts.slice(0, 4));
    }
  }, [alerts, flaredDots.length]);

  return (
    <section className="bg-surface border border-surface-border rounded-xl p-4 mb-6 shadow-md">
      {/* Top Header & Counters */}
      <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
        <div>
          <h2 className="text-xs uppercase tracking-wider text-cyan-400 font-mono font-semibold flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping"></span>
            Real-Time Packet Flow &amp; Diode Pipeline
          </h2>
          <p className="text-[11px] text-gray-400">
            Ambient flow rate synchronized with live backend throughput ({throughput.toFixed(1)}/s)
          </p>
        </div>

        {/* Counter Cards */}
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2 bg-surface-card border border-surface-border px-3 py-1.5 rounded-lg">
            <span className="text-xs text-gray-400">Flows Scanned:</span>
            <span className="font-mono text-sm font-bold text-gray-100">{scannedFlows.toLocaleString()}</span>
          </div>
          <div className="flex items-center space-x-2 bg-red-950/40 border border-red-500/30 px-3 py-1.5 rounded-lg">
            <span className="text-xs text-red-400">Threats Flagged:</span>
            <span className="font-mono text-sm font-bold text-red-400">{flaggedThreats.toLocaleString()}</span>
          </div>
          <button
            onClick={() => setIsPaused(!isPaused)}
            className="flex items-center space-x-1 px-2.5 py-1.5 rounded-lg bg-surface-card hover:bg-surface-hover border border-surface-border text-xs text-gray-300 transition-colors"
          >
            {isPaused ? <Play className="w-3.5 h-3.5 text-emerald-400" /> : <Pause className="w-3.5 h-3.5 text-amber-400" />}
            <span>{isPaused ? 'Resume' : 'Pause'}</span>
          </button>
        </div>
      </div>

      {/* Visual Diode Pipeline Track */}
      <div className="relative h-20 border-y border-surface-border/60 my-2 bg-surface-card/40 rounded-lg overflow-hidden flex items-center">
        {/* Stage Nodes */}
        <div className="absolute left-[5%] top-1/2 -translate-y-1/2 text-center z-10">
          <div className="w-8 h-8 rounded-full bg-surface-hover border border-gray-600 flex items-center justify-center text-gray-400 mx-auto">
            <Router className="w-4 h-4" />
          </div>
          <span className="text-[10px] font-mono text-gray-400 mt-1 block">Traffic</span>
        </div>

        <div className="absolute left-[33%] top-1/2 -translate-y-1/2 text-center z-10">
          <div className="w-8 h-8 rounded-full bg-surface-hover border border-cyan-500/40 flex items-center justify-center text-cyan-400 mx-auto shadow-[0_0_10px_rgba(0,240,255,0.15)]">
            <ArrowRightLeft className="w-4 h-4" />
          </div>
          <span className="text-[10px] font-mono text-cyan-400 mt-1 block">Diode</span>
        </div>

        <div className="absolute left-[66%] top-1/2 -translate-y-1/2 text-center z-10">
          <div className="w-8 h-8 rounded-full bg-surface-hover border border-purple-500/40 flex items-center justify-center text-purple-400 mx-auto shadow-[0_0_10px_rgba(168,85,247,0.15)]">
            <Cpu className="w-4 h-4" />
          </div>
          <span className="text-[10px] font-mono text-purple-400 mt-1 block">Detectors</span>
        </div>

        <div className="absolute right-[5%] top-1/2 -translate-y-1/2 text-center z-10">
          <div className="w-8 h-8 rounded-full bg-surface-hover border border-emerald-500/40 flex items-center justify-center text-emerald-400 mx-auto shadow-[0_0_10px_rgba(16,185,129,0.15)]">
            <LayoutDashboard className="w-4 h-4" />
          </div>
          <span className="text-[10px] font-mono text-emerald-400 mt-1 block">Dashboard</span>
        </div>

        {/* Connecting Lane line */}
        <div className="absolute left-[8%] right-[8%] top-1/2 h-[2px] bg-gradient-to-r from-gray-700 via-cyan-900 to-purple-900 -translate-y-1/2 z-0" />

        {/* Animated Traffic Dots */}
        <div className="absolute left-[8%] right-[8%] top-0 bottom-0 pointer-events-auto">
          {dots.map((dot) => (
            <button
              key={dot.id}
              onClick={() => dot.alertObj && selectAlert(dot.alertObj.id)}
              disabled={!dot.isThreat}
              title={dot.isThreat ? `Flared Alert: ${dot.alertObj?.threat_classification}` : 'Clean Traffic'}
              className={`absolute top-1/2 -translate-y-1/2 rounded-full transition-all cursor-pointer ${
                dot.isThreat
                  ? 'w-4 h-4 bg-red-500 ring-4 ring-red-500/40 shadow-[0_0_12px_#ef4444] z-20 animate-pulse'
                  : 'w-2 h-2 bg-cyan-400/70 shadow-[0_0_6px_#00f0ff] z-10 opacity-75'
              }`}
              style={{
                animation: `flowAnimation ${dot.durationSec}s linear forwards`,
              }}
            />
          ))}
        </div>
      </div>

      {/* Flared Alert Quick Rows */}
      {flaredDots.length > 0 && (
        <div className="mt-3">
          <div className="text-[11px] font-mono text-gray-400 mb-1.5 flex items-center justify-between">
            <span>Recent Flared Threats (click to open detail):</span>
            <span className="text-[10px] text-gray-400">Synced with main store</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
            {flaredDots.map((alert) => {
              const sev = getSeverityBadgeStyle(alert.severity);
              return (
                <div
                  key={alert.id}
                  onClick={() => selectAlert(alert.id)}
                  className="bg-surface-card hover:bg-surface-hover border border-surface-border hover:border-red-500/40 rounded-lg p-2.5 cursor-pointer transition-all flex items-center justify-between group"
                >
                  <div className="flex items-center space-x-2 truncate">
                    <AlertCircle className="w-4 h-4 text-red-400 shrink-0 group-hover:scale-110 transition-transform" />
                    <div className="truncate">
                      <p className="text-xs font-semibold text-gray-200 truncate">{alert.threat_classification}</p>
                      <p className="text-[10px] font-mono text-gray-400">{formatTimestamp(alert.timestamp)}</p>
                    </div>
                  </div>
                  <div className="text-right ml-2 shrink-0">
                    <span className="text-xs font-mono font-semibold text-red-400 block">
                      {formatConfidence(alert.confidence)}
                    </span>
                    <span className={`text-[9px] font-mono px-1 py-0.5 rounded border ${sev.bg} ${sev.text} ${sev.border}`}>
                      {alert.severity}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Inline Animation keyframes */}
      <style>{`
        @keyframes flowAnimation {
          0% { left: 0%; opacity: 0.2; }
          10% { opacity: 1; }
          90% { opacity: 1; }
          100% { left: 92%; opacity: 0.1; }
        }
      `}</style>
    </section>
  );
};
