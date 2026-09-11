/**
 * Severity and risk tier color mapping.
 * Crimson Dark Premium Design System tokens.
 */

export const TIER_COLORS = {
  critical: 'var(--sev-critical)',
  high: 'var(--sev-high)',
  medium: 'var(--sev-medium)',
  low: 'var(--sev-low)',
  clean: 'var(--sev-clean)',
  info: 'var(--sev-info)',
};

export const TIER_COLORS_RAW = {
  critical: '#EF4444',
  high: '#F97316',
  medium: '#FACC15',
  low: '#38BDF8',
  clean: '#10B981',
  info: '#64748B',
};

export function getTierFromScore(score) {
  if (score >= 75) return 'critical';
  if (score >= 50) return 'high';
  if (score >= 25) return 'medium';
  return 'clean';
}

export function getTierColor(tier) {
  return TIER_COLORS[String(tier).toLowerCase()] || TIER_COLORS.info;
}

export function getTierColorRaw(tier) {
  return TIER_COLORS_RAW[String(tier).toLowerCase()] || TIER_COLORS_RAW.info;
}

export function getBarColor(score) {
  if (score >= 75) return TIER_COLORS_RAW.critical;
  if (score >= 50) return TIER_COLORS_RAW.high;
  if (score >= 25) return TIER_COLORS_RAW.medium;
  return TIER_COLORS_RAW.clean;
}
