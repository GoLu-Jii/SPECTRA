import { SeverityLevel } from '../types';

/**
 * Format raw confidence number (e.g., 0.9996) into a percentage display string (e.g., "99.96%")
 * Note: Raw numeric confidence remains untouched in state.
 */
export function formatConfidence(confidence: number | undefined | null): string {
  if (confidence === undefined || confidence === null || isNaN(confidence)) {
    return '0.00%';
  }
  // Convert 0.0-1.0 range to percentage, handle values already > 1 gracefully
  const pct = confidence <= 1.0 ? confidence * 100 : confidence;
  return `${pct.toFixed(2)}%`;
}

/**
 * Get visual styling tokens for Severity levels.
 * Includes neutral fallback for unknown/future severity strings.
 */
export function getSeverityBadgeStyle(severity: SeverityLevel): {
  bg: string;
  text: string;
  border: string;
  dotBg: string;
  label: string;
} {
  const normalized = (severity || '').toUpperCase();

  switch (normalized) {
    case 'CRITICAL':
      return {
        bg: 'bg-red-950/40',
        text: 'text-red-400',
        border: 'border-red-500/30',
        dotBg: 'bg-red-500',
        label: 'CRITICAL',
      };
    case 'HIGH':
      return {
        bg: 'bg-orange-950/40',
        text: 'text-orange-400',
        border: 'border-orange-500/30',
        dotBg: 'bg-orange-500',
        label: 'HIGH',
      };
    case 'MEDIUM':
      return {
        bg: 'bg-amber-950/40',
        text: 'text-amber-300',
        border: 'border-amber-500/30',
        dotBg: 'bg-amber-400',
        label: 'MEDIUM',
      };
    case 'LOW':
      return {
        bg: 'bg-blue-950/40',
        text: 'text-blue-400',
        border: 'border-blue-500/30',
        dotBg: 'bg-blue-400',
        label: 'LOW',
      };
    default:
      // Neutral fallback color for any unknown or future severity
      return {
        bg: 'bg-gray-800/40',
        text: 'text-gray-400',
        border: 'border-gray-600/30',
        dotBg: 'bg-gray-400',
        label: normalized || 'UNKNOWN',
      };
  }
}

/**
 * Visual styling & chart colors for Threat Classifications.
 * Dynamic fallback styling ensures new/unseen detector threat classes render smoothly without breaking UI.
 */
const THREAT_COLOR_MAP: Record<string, { hex: string; badgeText: string; bg: string }> = {
  DDoS: { hex: '#c2414b', badgeText: 'text-red-400', bg: 'bg-red-500/10' },
  DGA_DOMAIN: { hex: '#7352a5', badgeText: 'text-purple-400', bg: 'bg-purple-500/10' },
  BOTNET_C2_BEACONING: { hex: '#c4662d', badgeText: 'text-orange-400', bg: 'bg-orange-500/10' },
  MALWARE_TLS: { hex: '#16758a', badgeText: 'text-cyan-400', bg: 'bg-cyan-500/10' },
  RECON_PORT_SCAN: { hex: '#ad7a16', badgeText: 'text-amber-400', bg: 'bg-amber-500/10' },
  DNS_TUNNELLING: { hex: '#8c4f75', badgeText: 'text-pink-400', bg: 'bg-pink-500/10' },
};

// Neutral fallback palette for dynamic threat classes
const FALLBACK_HEX_COLORS = ['#356da8', '#26734d', '#7352a5', '#ad7a16', '#16758a', '#8c4f75'];

export function getThreatColorHex(threatClass: string): string {
  if (THREAT_COLOR_MAP[threatClass]) {
    return THREAT_COLOR_MAP[threatClass].hex;
  }
  // Generate deterministic fallback color based on string hash
  let hash = 0;
  for (let i = 0; i < threatClass.length; i++) {
    hash = threatClass.charCodeAt(i) + ((hash << 5) - hash);
  }
  const index = Math.abs(hash) % FALLBACK_HEX_COLORS.length;
  return FALLBACK_HEX_COLORS[index];
}

export function formatThreatLabel(threatClass: string): string {
  if (!threatClass) return 'UNKNOWN_THREAT';
  // Standardize display label e.g., BOTNET_C2_BEACONING -> Botnet C2 Beaconing
  return threatClass.replace(/_/g, ' ');
}

/**
 * Format ISO timestamp into clean 24-hour time HH:mm:ss
 */
export function formatTimestamp(isoString: string): string {
  if (!isoString) return '--:--:--';
  try {
    const date = new Date(isoString);
    if (isNaN(date.getTime())) return isoString;
    return date.toTimeString().split(' ')[0];
  } catch {
    return isoString;
  }
}

/**
 * Format full date & time for detail panel
 */
export function formatFullDateTime(isoString: string): string {
  if (!isoString) return 'N/A';
  try {
    const date = new Date(isoString);
    if (isNaN(date.getTime())) return isoString;
    return `${date.toLocaleDateString()} ${date.toTimeString().split(' ')[0]}.${String(date.getMilliseconds()).padStart(3, '0')}`;
  } catch {
    return isoString;
  }
}
