import React, { useMemo } from 'react';
import { useSpectraStore } from '../store/useSpectraStore';
import { getThreatColorHex, formatThreatLabel } from '../utils/formatters';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { BarChart3, AlertOctagon } from 'lucide-react';

export const ThreatSummaryChart: React.FC = () => {
  const alerts = useSpectraStore((s) => s.alerts);

  /**
   * Dynamically build chart data from loaded alerts.
   * STRICT REQUIREMENT: Do not hardcode fixed threat types!
   * Counts whatever threat_classification values exist in active alert data.
   */
  const chartData = useMemo(() => {
    const counts: Record<string, number> = {};

    alerts.forEach((alert) => {
      const cls = alert.threat_classification || 'UNKNOWN';
      counts[cls] = (counts[cls] || 0) + 1;
    });

    return Object.entries(counts).map(([threatClass, count]) => ({
      threatClass,
      displayName: formatThreatLabel(threatClass),
      count,
      color: getThreatColorHex(threatClass),
    }));
  }, [alerts]);

  if (alerts.length === 0) {
    return (
      <section className="bg-surface border border-surface-border rounded-xl p-5 mb-6 shadow-md">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-gray-200 uppercase tracking-wider font-mono flex items-center gap-2">
            <BarChart3 className="w-4 h-4 text-cyan-400" />
            Threat Summary Distribution
          </h2>
        </div>
        <div className="h-44 flex flex-col items-center justify-center text-center text-gray-500 border border-dashed border-gray-800 rounded-lg">
          <AlertOctagon className="w-8 h-8 text-gray-600 mb-2" />
          <p className="text-xs font-mono">No threat data currently loaded</p>
          <p className="text-[11px] text-gray-400 mt-1">
            Charts will generate dynamically as alerts arrive
          </p>
        </div>
      </section>
    );
  }

  return (
    <section className="bg-surface border border-surface-border rounded-xl p-5 mb-6 shadow-md">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-sm font-semibold text-gray-200 uppercase tracking-wider font-mono flex items-center gap-2">
            <BarChart3 className="w-4 h-4 text-cyan-400" />
            Dynamic Threat Distribution Summary
          </h2>
          <p className="text-[11px] text-gray-400">
            Dynamically rendered across {chartData.length} unique active threat classes
          </p>
        </div>
        <div className="flex items-center space-x-2 text-xs font-mono text-gray-400">
          <span>Total Alerts:</span>
          <span className="font-bold text-cyan-400">{alerts.length}</span>
        </div>
      </div>

      <div className="h-52 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 25 }}>
            <XAxis
              dataKey="displayName"
              stroke="#6b7280"
              fontSize={11}
              fontFamily="JetBrains Mono, monospace"
              tickLine={false}
              interval={0}
              angle={-15}
              textAnchor="end"
            />
            <YAxis
              stroke="#6b7280"
              fontSize={11}
              fontFamily="JetBrains Mono, monospace"
              tickLine={false}
              allowDecimals={false}
            />
            <Tooltip
              content={({ active, payload }) => {
                if (active && payload && payload.length) {
                  const data = payload[0].payload;
                  return (
                    <div className="bg-surface-card border border-surface-border p-2.5 rounded-lg shadow-xl font-mono text-xs">
                      <p className="font-bold text-gray-200">{data.displayName}</p>
                      <p className="text-gray-400 mt-1">
                        Alert Count: <span className="text-cyan-400 font-bold">{data.count}</span>
                      </p>
                      <p className="text-[10px] text-gray-400">
                        {((data.count / alerts.length) * 100).toFixed(1)}% of total alerts
                      </p>
                    </div>
                  );
                }
                return null;
              }}
            />
            <Bar dataKey="count" radius={[4, 4, 0, 0]} maxBarSize={50}>
              {chartData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </section>
  );
};
