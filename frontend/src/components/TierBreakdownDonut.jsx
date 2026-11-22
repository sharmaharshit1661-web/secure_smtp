import { useId } from 'react';

const TIERS = [
  { key: 'critical', label: 'Critical', color: 'var(--sev-critical)' },
  { key: 'high', label: 'High', color: 'var(--sev-high)' },
  { key: 'medium', label: 'Medium', color: 'var(--sev-medium)' },
  { key: 'clean', label: 'Low risk', color: 'var(--sev-clean)' },
  { key: 'unknown', label: 'Unknown', color: 'var(--sev-info)' },
];

export default function TierBreakdownDonut({ counts, selectedTier = 'ALL', onSelectTier }) {
  const titleId = useId();
  const total = TIERS.reduce((sum, tier) => sum + (counts[tier.key] || 0), 0);
  const slices = TIERS.map((tier, index) => ({
    ...tier,
    value: counts[tier.key] || 0,
    offset: total ? TIERS.slice(0, index).reduce((sum, item) => sum + (counts[item.key] || 0), 0) / total * 100 : 0,
    percent: total ? (counts[tier.key] || 0) / total * 100 : 0,
  }));

  return <div className="risk-donut">
    <svg viewBox="0 0 200 200" role="img" aria-labelledby={titleId}>
      <title id={titleId}>{total} hosts. {slices.map(slice => `${slice.label}: ${slice.value}`).join('. ')}.</title>
      <circle cx="100" cy="100" r="76" fill="none" stroke="var(--bg-elevated)" strokeWidth="20" />
      <g transform="rotate(-90 100 100)" fill="none" strokeWidth="20">
        {slices.filter(slice => slice.value > 0).map(slice => <circle
          key={slice.key} cx="100" cy="100" r="76" pathLength="100"
          stroke={slice.color} strokeDasharray={`${slice.percent} ${100 - slice.percent}`}
          strokeDashoffset={-slice.offset}
          opacity={selectedTier === 'ALL' || selectedTier === slice.key.toUpperCase() ? 1 : .25}
        />)}
      </g>
      <text x="100" y="99" className="risk-donut-total" textAnchor="middle">{total}</text>
      <text x="100" y="121" className="risk-donut-label" textAnchor="middle">hosts</text>
    </svg>
    <div className="risk-donut-legend" role="group" aria-label="Filter hosts by risk">
      {slices.filter(slice => slice.key !== 'unknown' || slice.value > 0).map(slice => <button
        key={slice.key} type="button" aria-pressed={selectedTier === slice.key.toUpperCase()}
        onClick={() => onSelectTier(selectedTier === slice.key.toUpperCase() ? 'ALL' : slice.key.toUpperCase())}
      ><i style={{ background: slice.color }} /><span>{slice.label}</span><strong>{slice.value}</strong><small>{Math.round(slice.percent)}%</small></button>)}
    </div>
  </div>;
}
