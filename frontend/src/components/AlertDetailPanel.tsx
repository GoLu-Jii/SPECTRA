import React from 'react';
import { useSpectraStore } from '../store/useSpectraStore';
import {
  formatConfidence,
  formatFullDateTime,
  getSeverityBadgeStyle,
  getThreatColorHex,
  formatThreatLabel,
} from '../utils/formatters';
import { X, ShieldAlert, FileText, AlertTriangle, Network, Copy, Check } from 'lucide-react';

export const AlertDetailPanel: React.FC = () => {
  const selectedAlertId = useSpectraStore((s) => s.selectedAlertId);
  const selectedAlertDetail = useSpectraStore((s) => s.selectedAlertDetail);
  const isDetailLoading = useSpectraStore((s) => s.isDetailLoading);
  const detailError = useSpectraStore((s) => s.detailError);
  const closeAlertDetail = useSpectraStore((s) => s.closeAlertDetail);

  const [copied, setCopied] = React.useState(false);

  if (!selectedAlertId) return null;

  const handleCopyJson = () => {
    if (selectedAlertDetail) {
      navigator.clipboard.writeText(JSON.stringify(selectedAlertDetail, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  /**
   * Generic Evidence Value Renderer
   * Renders primitives, arrays, and nested objects dynamically without fixed field assumptions.
   */
  const renderGenericValue = (value: any): React.ReactNode => {
    if (value === null || value === undefined) {
      return <span className="text-gray-400 font-mono italic">null</span>;
    }

    if (typeof value === 'boolean') {
      return (
        <span
          className={`font-mono text-xs px-2 py-0.5 rounded ${
            value ? 'bg-emerald-950/60 text-emerald-400 border border-emerald-500/30' : 'bg-red-950/60 text-red-400 border border-red-500/30'
          }`}
        >
          {value ? 'TRUE' : 'FALSE'}
        </span>
      );
    }

    if (typeof value === 'number') {
      return <span className="font-mono text-cyan-300 font-semibold">{value}</span>;
    }

    if (typeof value === 'string') {
      // Highlight hashes or IP addresses
      if (value.length > 25 || value.includes('→') || value.includes(':')) {
        return <span className="font-mono text-xs text-gray-200 break-all bg-surface border border-surface-border p-1 rounded block">{value}</span>;
      }
      return <span className="text-gray-200 font-mono">{value}</span>;
    }

    if (Array.isArray(value)) {
      if (value.length === 0) return <span className="text-gray-400 font-mono text-xs">[ Empty Array ]</span>;
      return (
        <div className="space-y-1 mt-1">
          {value.map((item, idx) => (
            <div key={idx} className="flex items-start space-x-1 text-xs font-mono text-cyan-200">
              <span className="text-gray-400 select-none">•</span>
              <span className="break-all">{typeof item === 'object' ? JSON.stringify(item) : String(item)}</span>
            </div>
          ))}
        </div>
      );
    }

    if (typeof value === 'object') {
      return (
        <div className="bg-surface border border-surface-border rounded-lg p-2.5 space-y-1.5 mt-1 font-mono text-xs">
          {Object.entries(value).map(([k, v]) => (
            <div key={k} className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 border-b border-surface-border/40 pb-1 last:border-0 last:pb-0">
              <span className="text-gray-400 font-medium">{k}:</span>
              <div>{renderGenericValue(v)}</div>
            </div>
          ))}
        </div>
      );
    }

    return <span className="font-mono text-gray-300">{String(value)}</span>;
  };

  const alert = selectedAlertDetail;
  const sevStyle = alert ? getSeverityBadgeStyle(alert.severity) : null;
  const threatColor = alert ? getThreatColorHex(alert.threat_classification) : '#6b7280';

  return (
    <div className="fixed inset-0 z-50 overflow-hidden flex justify-end bg-black/60 backdrop-blur-sm animate-fade-in">
      {/* Backdrop click to close */}
      <div className="absolute inset-0" onClick={closeAlertDetail} />

      {/* Slide-over Panel */}
      <div className="relative w-full max-w-2xl bg-surface border-l border-surface-border h-full shadow-2xl flex flex-col z-10 animate-slide-in-right">
        {/* Header */}
        <div className="p-5 border-b border-surface-border bg-surface-card/80 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-surface-hover border border-surface-border">
              <ShieldAlert className="w-5 h-5 text-red-400" />
            </div>
            <div>
              <h2 className="font-mono text-base font-bold text-gray-100 uppercase tracking-wider flex items-center gap-2">
                ALERT_DETAIL <span className="text-xs text-gray-400 font-normal">({selectedAlertId})</span>
              </h2>
              <p className="text-xs text-gray-400 font-mono">
                Source Endpoint: GET /alerts/{selectedAlertId}
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            {alert && (
              <button
                onClick={handleCopyJson}
                className="p-2 rounded-lg bg-surface-card hover:bg-surface-hover border border-surface-border text-gray-300 hover:text-white transition-colors"
                title="Copy raw JSON payload"
              >
                {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
              </button>
            )}
            <button
              onClick={closeAlertDetail}
              className="p-2 rounded-lg bg-surface-card hover:bg-surface-hover border border-surface-border text-gray-300 hover:text-white transition-colors"
              title="Close panel"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Loading State */}
          {isDetailLoading && (
            <div className="h-64 flex flex-col items-center justify-center space-y-3">
              <div className="w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
              <p className="font-mono text-xs text-gray-400">Fetching alert record from backend data layer...</p>
            </div>
          )}

          {/* 404 Handled State */}
          {!isDetailLoading && detailError && (
            <div className="bg-red-950/30 border border-red-500/40 rounded-xl p-5 text-center">
              <AlertTriangle className="w-10 h-10 text-red-400 mx-auto mb-2" />
              <h3 className="font-mono font-bold text-red-400 text-sm">Alert Not Found (404)</h3>
              <p className="text-xs text-gray-300 mt-1 font-mono">{detailError}</p>
              <p className="text-[11px] text-gray-400 mt-3">
                This state is expected when requesting a non-existent or purged alert ID.
              </p>
            </div>
          )}

          {/* Alert Content */}
          {!isDetailLoading && alert && sevStyle && (
            <>
              {/* Primary Overview Card */}
              <div className="bg-surface-card border border-surface-border rounded-xl p-4 space-y-4">
                <div className="flex items-center justify-between border-b border-surface-border/60 pb-3">
                  <div>
                    <span className="text-[10px] font-mono text-gray-400 uppercase">Threat Classification</span>
                    <div className="flex items-center space-x-2 mt-0.5">
                      <span className="w-3 h-3 rounded-full" style={{ backgroundColor: threatColor }} />
                      <span className="text-lg font-mono font-bold text-gray-100">
                        {formatThreatLabel(alert.threat_classification)}
                      </span>
                    </div>
                  </div>

                  <span
                    className={`inline-flex items-center space-x-1.5 px-3 py-1 rounded-md border text-xs font-mono font-bold ${sevStyle.bg} ${sevStyle.text} ${sevStyle.border}`}
                  >
                    <span className={`w-2 h-2 rounded-full ${sevStyle.dotBg}`} />
                    <span>{sevStyle.label}</span>
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-4 text-xs font-mono">
                  <div>
                    <span className="text-gray-400 text-[11px]">Backend Confidence:</span>
                    <p className="text-lg font-bold text-red-400">{formatConfidence(alert.confidence)}</p>
                    <span className="text-[10px] text-gray-400 font-normal">Raw value: {alert.confidence}</span>
                  </div>

                  <div>
                    <span className="text-gray-400 text-[11px]">Event Timestamp:</span>
                    <p className="text-xs text-gray-200 font-semibold mt-1">{formatFullDateTime(alert.timestamp)}</p>
                  </div>
                </div>
              </div>

              {/* Flow Identifier Section */}
              <div className="bg-surface-card border border-surface-border rounded-xl p-4">
                <h3 className="text-xs font-mono text-gray-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <Network className="w-3.5 h-3.5 text-cyan-400" />
                  Flow Identifier (flow_identifier)
                </h3>
                <div className="bg-background border border-surface-border rounded-lg p-3 font-mono text-sm text-cyan-300 font-semibold break-all select-all">
                  {alert.flow_identifier || 'N/A'}
                </div>
              </div>

              {/* Dynamic Evidence Section */}
              <div className="bg-surface-card border border-surface-border rounded-xl p-4">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-xs font-mono text-gray-400 uppercase tracking-wider flex items-center gap-1.5">
                    <FileText className="w-3.5 h-3.5 text-purple-400" />
                    Detector Evidence Telemetry
                  </h3>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-950/60 text-purple-300 border border-purple-500/30">
                    Generic Dictionary ({Object.keys(alert.evidence || {}).length} fields)
                  </span>
                </div>

                {!alert.evidence || Object.keys(alert.evidence).length === 0 ? (
                  <p className="text-xs font-mono text-gray-500 italic p-3 text-center border border-dashed border-gray-800 rounded-lg">
                    No evidence dictionary returned for this alert.
                  </p>
                ) : (
                  <div className="space-y-3">
                    {Object.entries(alert.evidence).map(([key, val]) => (
                      <div
                        key={key}
                        className="bg-surface border border-surface-border rounded-lg p-3 hover:border-gray-600/50 transition-colors"
                      >
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-xs font-mono font-semibold text-purple-300">{key}</span>
                          <span className="text-[10px] font-mono text-gray-400 uppercase">{typeof val}</span>
                        </div>
                        <div className="mt-1">{renderGenericValue(val)}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </>
          )}
        </div>

        {/* Panel Footer */}
        <div className="p-4 border-t border-surface-border bg-surface-card/60 flex items-center justify-between text-xs font-mono text-gray-400">
          <span>Detector-owned metrics (frontend display only)</span>
          <button
            onClick={closeAlertDetail}
            className="px-3 py-1.5 rounded-lg bg-surface hover:bg-surface-hover border border-surface-border text-gray-200 transition-colors"
          >
            Close Panel
          </button>
        </div>
      </div>
    </div>
  );
};
