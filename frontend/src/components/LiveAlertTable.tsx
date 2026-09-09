import React, { useState } from 'react';
import { useSpectraStore } from '../store/useSpectraStore';
import {
  formatConfidence,
  formatTimestamp,
  getSeverityBadgeStyle,
  getThreatColorHex,
  formatThreatLabel,
} from '../utils/formatters';
import { AlertCircle, ChevronRight, Search, ShieldAlert } from 'lucide-react';

export const LiveAlertTable: React.FC = () => {
  const alerts = useSpectraStore((s) => s.alerts);
  const selectedAlertId = useSpectraStore((s) => s.selectedAlertId);
  const selectAlert = useSpectraStore((s) => s.selectAlert);
  const simulatedEmptyAlerts = useSpectraStore((s) => s.simulatedEmptyAlerts);

  const [filterQuery, setFilterQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');

  // Filter alerts based on search query and severity
  const filteredAlerts = alerts.filter((alert) => {
    const matchesSearch =
      filterQuery === '' ||
      alert.threat_classification.toLowerCase().includes(filterQuery.toLowerCase()) ||
      alert.flow_identifier.toLowerCase().includes(filterQuery.toLowerCase()) ||
      alert.id.toLowerCase().includes(filterQuery.toLowerCase());

    const matchesSeverity =
      severityFilter === 'ALL' || alert.severity.toUpperCase() === severityFilter.toUpperCase();

    return matchesSearch && matchesSeverity;
  });

  return (
    <section className="bg-surface border border-surface-border rounded-xl shadow-md overflow-hidden mb-6">
      {/* Table Header & Controls */}
      <div className="p-4 border-b border-surface-border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 bg-surface-card/50">
        <div>
          <h2 className="text-sm font-semibold text-gray-100 uppercase tracking-wider font-mono flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-red-400" />
            Live Threat Alert Feed
          </h2>
          <p className="text-[11px] text-gray-400">
            Real-time alert events prepended directly from WebSocket live stream
          </p>
        </div>

        {/* Filter Inputs */}
        <div className="flex items-center space-x-2 w-full sm:w-auto">
          {/* Search Box */}
          <div className="relative flex-1 sm:w-64">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-400" />
            <input
              type="text"
              placeholder="Search threat, IP, flow..."
              value={filterQuery}
              onChange={(e) => setFilterQuery(e.target.value)}
              className="w-full bg-surface border border-surface-border rounded-lg pl-8 pr-3 py-1.5 text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:border-cyan-500/60 font-mono"
            />
          </div>

          {/* Severity Dropdown Filter */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-surface border border-surface-border rounded-lg px-2.5 py-1.5 text-xs text-gray-300 focus:outline-none focus:border-cyan-500/60 font-mono"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>
        </div>
      </div>

      {/* Table Body */}
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-surface-card border-b border-surface-border text-[11px] font-mono text-gray-400 uppercase tracking-wider">
              <th className="py-3 px-4">Time</th>
              <th className="py-3 px-4">Threat Classification</th>
              <th className="py-3 px-4">Flow Identifier</th>
              <th className="py-3 px-4">Confidence</th>
              <th className="py-3 px-4">Severity</th>
              <th className="py-3 px-4 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-surface-border text-xs">
            {filteredAlerts.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-12 text-center text-gray-500">
                  <div className="flex flex-col items-center justify-center space-y-2">
                    <AlertCircle className="w-8 h-8 text-gray-600" />
                    <p className="font-mono text-sm">
                      {simulatedEmptyAlerts
                        ? 'Simulated Empty Alert List'
                        : alerts.length === 0
                        ? 'No alerts detected yet. Waiting for live telemetry stream...'
                        : 'No alerts match current search filter'}
                    </p>
                    <p className="text-[11px] text-gray-400">
                      New alerts will automatically appear here in real-time
                    </p>
                  </div>
                </td>
              </tr>
            ) : (
              filteredAlerts.map((alert, index) => {
                const sevStyle = getSeverityBadgeStyle(alert.severity);
                const threatColor = getThreatColorHex(alert.threat_classification);
                const isSelected = selectedAlertId === alert.id;
                const isFirst = index === 0;

                return (
                  <tr
                    key={alert.id}
                    onClick={() => selectAlert(alert.id)}
                    className={`group cursor-pointer transition-colors duration-150 ${
                      isSelected
                        ? 'bg-cyan-950/40 border-l-4 border-l-cyan-400'
                        : 'hover:bg-surface-hover'
                    } ${isFirst ? 'animate-slide-down bg-cyan-950/10' : ''}`}
                  >
                    {/* Time */}
                    <td className="py-3 px-4 font-mono text-gray-400 whitespace-nowrap">
                      {formatTimestamp(alert.timestamp)}
                    </td>

                    {/* Threat Classification */}
                    <td className="py-3 px-4 font-medium whitespace-nowrap">
                      <div className="flex items-center space-x-2">
                        <span
                          className="w-2 h-2 rounded-full shrink-0"
                          style={{ backgroundColor: threatColor }}
                        />
                        <span className="text-gray-200 group-hover:text-cyan-300 font-mono">
                          {formatThreatLabel(alert.threat_classification)}
                        </span>
                      </div>
                    </td>

                    {/* Flow Identifier (CRITICAL FIELD NAME: flow_identifier) */}
                    <td className="py-3 px-4 font-mono text-gray-300 whitespace-nowrap text-xs">
                      <span className="bg-surface border border-surface-border px-2 py-0.5 rounded">
                        {alert.flow_identifier || 'N/A'}
                      </span>
                    </td>

                    {/* Confidence (Formatted percentage e.g. 99.96%) */}
                    <td className="py-3 px-4 font-mono font-semibold text-gray-200 whitespace-nowrap">
                      <span className={alert.confidence >= 0.9 ? 'text-red-400' : 'text-amber-300'}>
                        {formatConfidence(alert.confidence)}
                      </span>
                    </td>

                    {/* Severity Badge */}
                    <td className="py-3 px-4 whitespace-nowrap">
                      <span
                        className={`inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded-md border text-[11px] font-mono font-semibold ${sevStyle.bg} ${sevStyle.text} ${sevStyle.border}`}
                      >
                        <span className={`w-1.5 h-1.5 rounded-full ${sevStyle.dotBg}`} />
                        <span>{sevStyle.label}</span>
                      </span>
                    </td>

                    {/* Action */}
                    <td className="py-3 px-4 text-right whitespace-nowrap font-mono text-gray-400 group-hover:text-cyan-400">
                      <span className="inline-flex items-center gap-1 text-[11px] font-medium">
                        View Details
                        <ChevronRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
                      </span>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Footer Info */}
      <div className="p-3 bg-surface-card/40 border-t border-surface-border flex items-center justify-between text-xs text-gray-400 font-mono">
        <span>Showing {filteredAlerts.length} of {alerts.length} total alerts</span>
        <span>Click any row or flared dot to inspect evidence</span>
      </div>
    </section>
  );
};
