import React from 'react';
import { useSpectraStore } from '../store/useSpectraStore';
import { Activity, AlertTriangle, Layers, Zap, Clock, ShieldAlert } from 'lucide-react';

export const StatsRow: React.FC = () => {
  const stats = useSpectraStore((s) => s.stats);
  const systemError = useSpectraStore((s) => s.systemError);

  if (systemError || !stats) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 mb-6">
        {[...Array(6)].map((_, i) => (
          <div
            key={i}
            className="bg-surface-card/60 border border-surface-border/50 rounded-xl p-3.5 animate-pulse flex flex-col justify-between h-24"
          >
            <div className="h-3 w-20 bg-gray-800 rounded"></div>
            <div className="h-6 w-16 bg-gray-800 rounded mt-2"></div>
          </div>
        ))}
      </div>
    );
  }

  const alertsCount = stats.alerts_generated;

  const statCards = [
    {
      title: 'Events Processed',
      value: stats.events_processed?.toLocaleString() ?? '0',
      icon: Activity,
      color: 'text-cyan-400',
      borderColor: 'border-cyan-500/20',
      sub: `Received: ${stats.events_received?.toLocaleString() ?? '0'}`,
    },
    {
      title: 'Alerts Flagged',
      value: alertsCount.toString(),
      icon: AlertTriangle,
      color: 'text-red-400',
      borderColor: 'border-red-500/20',
      sub: `${((alertsCount / Math.max(stats.events_processed, 1)) * 100).toFixed(2)}% alert rate`,
    },
    {
      title: 'Throughput',
      value: `${stats.throughput?.toFixed(2) ?? '0.00'}/s`,
      icon: Zap,
      color: 'text-emerald-400',
      borderColor: 'border-emerald-500/20',
      sub: 'events per second',
    },
    {
      title: 'Queue Depth',
      value: stats.queue_depth?.toString() ?? '0',
      icon: Layers,
      color: stats.queue_depth > 5 ? 'text-amber-400' : 'text-blue-400',
      borderColor: 'border-blue-500/20',
      sub: stats.queue_depth === 0 ? 'Optimal (0 backlog)' : 'Pending backlog',
    },
    {
      title: 'Inference Latency',
      value: `${stats.inference_latency?.toFixed(2) ?? '0.00'} ms`,
      icon: Clock,
      color: 'text-purple-400',
      borderColor: 'border-purple-500/20',
      sub: `E2E: ${stats.end_to_end_latency?.toFixed(2) ?? '0.00'} ms`,
    },
    {
      title: 'Detector Errors',
      value: (stats.detector_failures + stats.malformed_events + stats.dropped_events).toString(),
      icon: ShieldAlert,
      color: stats.detector_failures > 0 ? 'text-red-400' : 'text-gray-400',
      borderColor: 'border-gray-500/20',
      sub: `${stats.detector_failures} failures / ${stats.dropped_events} dropped`,
    },
  ];

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mb-6">
      {statCards.map((card, idx) => {
        const IconComponent = card.icon;
        return (
          <div
            key={idx}
            className={`bg-surface-card border ${card.borderColor} rounded-xl p-3.5 shadow-sm hover:border-gray-600/50 transition-all duration-200 flex flex-col justify-between`}
          >
            <div className="flex items-center justify-between">
              <span className="text-xs text-gray-400 font-medium truncate">{card.title}</span>
              <IconComponent className={`w-4 h-4 ${card.color} opacity-80`} />
            </div>
            <div className="my-1.5">
              <span className={`text-xl sm:text-2xl font-mono font-bold tracking-tight ${card.color}`}>
                {card.value}
              </span>
            </div>
            <p className="text-[10px] text-gray-400 font-mono truncate">{card.sub}</p>
          </div>
        );
      })}
    </div>
  );
};
