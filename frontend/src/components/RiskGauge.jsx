import { useId } from 'react';
import { getTierColor } from '../utils/colors';
import { riskValue } from '../utils/telemetry';

export default function RiskGauge({ score, tier = 'info', size = 150 }) {
  const titleId = useId();
  const value = riskValue(score);
  const radius = (size - 20) / 2;
  const center = size / 2;
  const arc = `M ${center - radius} ${center} A ${radius} ${radius} 0 0 1 ${center + radius} ${center}`;
  return <svg width={size} height={size * .7} viewBox={`0 0 ${size} ${size * .7}`} role="img" aria-labelledby={titleId}>
    <title id={titleId}>{value == null ? 'Risk score unavailable' : `Risk score ${Math.round(value)} out of 100, ${tier}`}</title>
    <path d={arc} fill="none" stroke="var(--border)" strokeWidth="7" strokeLinecap="round" />
    {value != null && <path d={arc} fill="none" stroke={getTierColor(tier)} strokeWidth="7" strokeLinecap="round" pathLength="100" strokeDasharray={`${value} 100`} />}
    <text x={center} y={center - 10} textAnchor="middle" fill="var(--text-primary)" fontFamily="var(--font-heading)" fontSize={size * .22} fontWeight="500">{value == null ? '—' : Math.round(value)}</text>
    <text x={center} y={center + 10} textAnchor="middle" fill="var(--text-secondary)" fontFamily="var(--font-mono)" fontSize="11">/ 100</text>
  </svg>;
}
