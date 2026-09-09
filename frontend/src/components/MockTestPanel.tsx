import React from 'react';
import { useSpectraStore } from '../store/useSpectraStore';
import { generateNewMockAlert } from '../services/api/mockData';
import { Wrench, Power, ServerOff, ListX, AlertCircle, PlusCircle } from 'lucide-react';

interface MockTestPanelProps {
  onClose: () => void;
}

export const MockTestPanel: React.FC<MockTestPanelProps> = ({ onClose }) => {
  const simulatedOffline = useSpectraStore((s) => s.simulatedOffline);
  const simulatedNotReady = useSpectraStore((s) => s.simulatedNotReady);
  const simulatedEmptyAlerts = useSpectraStore((s) => s.simulatedEmptyAlerts);
  const toggleOffline = useSpectraStore((s) => s.toggleSimulatedOffline);
  const toggleNotReady = useSpectraStore((s) => s.toggleSimulatedNotReady);
  const toggleEmptyAlerts = useSpectraStore((s) => s.toggleSimulatedEmptyAlerts);
  const selectAlert = useSpectraStore((s) => s.selectAlert);
  const prependAlert = useSpectraStore((s) => s.prependAlert);

  const handleTest404 = () => {
    selectAlert('non_existent_alert_99999');
  };

  const handleEmitUnseenThreat = () => {
    const unknownThreats = [
      'ZERO_DAY_RCE_EXPLOIT',
      'EXFILTRATION_DNS_COVERT',
      'ANOMALOUS_ENCRYPTED_FLOW',
    ];
    const threat = unknownThreats[Math.floor(Math.random() * unknownThreats.length)];

    const customAlert = {
      ...generateNewMockAlert(),
      id: `alt_custom_${Date.now()}`,
      threat_classification: threat,
      severity: 'CRITICAL',
      evidence: {
        unseen_detector_metric_1: 99.4,
        unseen_detector_metric_2: 'Experimental telemetry payload',
        nested_unknown_data: {
          flag: true,
          vector: [1, 5, 99],
        },
      },
    };

    prependAlert(customAlert);
  };

  return (
    <div className="bg-purple-950/30 border border-purple-500/40 rounded-xl p-4 mb-6 shadow-lg backdrop-blur-md animate-slide-down">
      <div className="flex items-center justify-between border-b border-purple-500/30 pb-3 mb-3">
        <div className="flex items-center space-x-2">
          <Wrench className="w-4 h-4 text-purple-400" />
          <h3 className="font-mono text-xs font-bold uppercase tracking-wider text-purple-200">
            Mock Edge-Case Test Harness &amp; Scenario Simulator
          </h3>
        </div>
        <button
          onClick={onClose}
          className="text-xs font-mono text-gray-400 hover:text-white px-2 py-1 rounded bg-surface border border-surface-border"
        >
          Close Harness
        </button>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
        {/* Toggle Simulated Offline */}
        <button
          onClick={toggleOffline}
          className={`p-2.5 rounded-lg border font-mono text-xs text-left transition-all ${
            simulatedOffline
              ? 'bg-red-950/80 text-red-300 border-red-500 shadow-[0_0_10px_rgba(239,68,68,0.3)]'
              : 'bg-surface hover:bg-surface-hover text-gray-300 border-surface-border'
          }`}
        >
          <div className="flex items-center justify-between font-bold">
            <span className="flex items-center gap-1.5">
              <ServerOff className="w-3.5 h-3.5" /> Backend Offline
            </span>
            <span className="text-[10px] uppercase">{simulatedOffline ? 'ACTIVE' : 'OFF'}</span>
          </div>
          <p className="text-[10px] text-gray-400 mt-1">Simulate failed requests &amp; connection drop</p>
        </button>

        {/* Toggle Simulated Not Ready */}
        <button
          onClick={toggleNotReady}
          className={`p-2.5 rounded-lg border font-mono text-xs text-left transition-all ${
            simulatedNotReady
              ? 'bg-amber-950/80 text-amber-300 border-amber-500 shadow-[0_0_10px_rgba(245,158,11,0.3)]'
              : 'bg-surface hover:bg-surface-hover text-gray-300 border-surface-border'
          }`}
        >
          <div className="flex items-center justify-between font-bold">
            <span className="flex items-center gap-1.5">
              <Power className="w-3.5 h-3.5" /> Ready: False
            </span>
            <span className="text-[10px] uppercase">{simulatedNotReady ? 'ACTIVE' : 'OFF'}</span>
          </div>
          <p className="text-[10px] text-gray-400 mt-1">Simulate worker starting / replay</p>
        </button>

        {/* Toggle Empty Alerts */}
        <button
          onClick={toggleEmptyAlerts}
          className={`p-2.5 rounded-lg border font-mono text-xs text-left transition-all ${
            simulatedEmptyAlerts
              ? 'bg-blue-950/80 text-blue-300 border-blue-500 shadow-[0_0_10px_rgba(59,130,246,0.3)]'
              : 'bg-surface hover:bg-surface-hover text-gray-300 border-surface-border'
          }`}
        >
          <div className="flex items-center justify-between font-bold">
            <span className="flex items-center gap-1.5">
              <ListX className="w-3.5 h-3.5" /> Empty Alert List
            </span>
            <span className="text-[10px] uppercase">{simulatedEmptyAlerts ? 'ACTIVE' : 'OFF'}</span>
          </div>
          <p className="text-[10px] text-gray-400 mt-1">Test 0-alert table &amp; chart states</p>
        </button>

        {/* Trigger 404 Detail */}
        <button
          onClick={handleTest404}
          className="p-2.5 rounded-lg bg-surface hover:bg-surface-hover border border-surface-border text-gray-300 font-mono text-xs text-left transition-all"
        >
          <div className="flex items-center space-x-1.5 font-bold text-orange-400">
            <AlertCircle className="w-3.5 h-3.5" />
            <span>Test 404 Alert ID</span>
          </div>
          <p className="text-[10px] text-gray-400 mt-1">Opens detail panel with non-existent ID</p>
        </button>

        {/* Emit Unseen Threat Class */}
        <button
          onClick={handleEmitUnseenThreat}
          className="p-2.5 rounded-lg bg-surface hover:bg-surface-hover border border-surface-border text-gray-300 font-mono text-xs text-left transition-all"
        >
          <div className="flex items-center space-x-1.5 font-bold text-cyan-400">
            <PlusCircle className="w-3.5 h-3.5" />
            <span>Emit Unseen Threat</span>
          </div>
          <p className="text-[10px] text-gray-400 mt-1">Tests neutral fallback styling in UI</p>
        </button>
      </div>
    </div>
  );
};
