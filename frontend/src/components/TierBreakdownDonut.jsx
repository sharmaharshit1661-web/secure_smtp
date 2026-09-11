import { useState } from 'react';

const TIERS = [
  { key: 'critical', name: 'Critical', minScore: '≥ 75', color: '#EF4444', bgSoft: 'rgba(239, 68, 68, 0.12)', glow: 'rgba(239, 68, 68, 0.45)' },
  { key: 'high', name: 'High', minScore: '50–74', color: '#F97316', bgSoft: 'rgba(249, 115, 22, 0.12)', glow: 'rgba(249, 115, 22, 0.45)' },
  { key: 'medium', name: 'Medium', minScore: '25–49', color: '#FACC15', bgSoft: 'rgba(250, 204, 21, 0.12)', glow: 'rgba(250, 204, 21, 0.45)' },
  { key: 'clean', name: 'Healthy', minScore: '< 25', color: '#10B981', bgSoft: 'rgba(16, 185, 129, 0.12)', glow: 'rgba(16, 185, 129, 0.45)' },
];

export default function TierBreakdownDonut({
  critical = 0,
  high = 0,
  medium = 0,
  clean = 0,
  totalHosts = 0,
  onSelectTier,
}) {
  const [hoveredTier, setHoveredTier] = useState(null);

  const counts = {
    critical,
    high,
    medium,
    clean,
  };

  const total = totalHosts > 0 ? totalHosts : Object.values(counts).reduce((a, b) => a + b, 0);

  const radius = 72;
  const strokeWidth = 22;
  const circumference = 2 * Math.PI * radius;

  // Compute slice angles and offsets immutably
  const slices = TIERS.map((tier, index) => {
    const prevSum = TIERS.slice(0, index).reduce((acc, t) => acc + (counts[t.key] || 0), 0);
    const accumulatedFraction = total > 0 ? prevSum / total : 0;
    const val = counts[tier.key] || 0;
    const fraction = total > 0 ? val / total : 0;
    const dashLength = fraction * circumference;
    const dashSpace = circumference - dashLength;
    const offset = -accumulatedFraction * circumference;

    return {
      ...tier,
      value: val,
      percentage: total > 0 ? Math.round(fraction * 100) : 0,
      dashLength,
      dashSpace,
      offset,
    };
  });

  const activeSlice = hoveredTier ? slices.find((s) => s.key === hoveredTier) : null;

  return (
    <div className="tier-breakdown-wrapper">
      <div className="tier-donut-container">
        <svg
          viewBox="0 0 200 200"
          className="tier-donut-svg"
          style={{ width: '100%', height: '100%', maxWidth: '210px', maxHeight: '210px', overflow: 'visible' }}
        >
          <defs>
            <filter id="donutGlow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
            {TIERS.map((t) => (
              <linearGradient key={`grad-${t.key}`} id={`grad-${t.key}`} x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor={t.color} stopOpacity="1" />
                <stop offset="100%" stopColor={t.color} stopOpacity="0.75" />
              </linearGradient>
            ))}
          </defs>

          {/* Background Orbit Track */}
          <circle
            cx="100"
            cy="100"
            r={radius}
            fill="none"
            stroke="rgba(255, 255, 255, 0.035)"
            strokeWidth={strokeWidth}
          />

          {/* Decorative Outer Guide Ring (Mastercard Orbit Inspiration) */}
          <circle
            cx="100"
            cy="100"
            r={radius + strokeWidth / 2 + 8}
            fill="none"
            stroke="rgba(255, 255, 255, 0.025)"
            strokeWidth="1"
            strokeDasharray="3 5"
          />

          {/* Donut Slices */}
          <g transform="rotate(-90 100 100)">
            {slices.map((slice) => {
              if (slice.value === 0) return null;
              const isHovered = hoveredTier === slice.key;

              return (
                <circle
                  key={slice.key}
                  cx="100"
                  cy="100"
                  r={radius}
                  fill="none"
                  stroke={`url(#grad-${slice.key})`}
                  strokeWidth={isHovered ? strokeWidth + 4 : strokeWidth}
                  strokeDasharray={`${slice.dashLength} ${slice.dashSpace}`}
                  strokeDashoffset={slice.offset}
                  strokeLinecap={slices.filter((s) => s.value > 0).length === 1 ? 'butt' : 'round'}
                  style={{
                    transition: 'stroke-width 200ms ease, filter 200ms ease',
                    cursor: 'pointer',
                    filter: isHovered ? `drop-shadow(0 0 8px ${slice.glow})` : 'none',
                  }}
                  onMouseEnter={() => setHoveredTier(slice.key)}
                  onMouseLeave={() => setHoveredTier(null)}
                  onClick={() => onSelectTier && onSelectTier(slice.key.toUpperCase())}
                />
              );
            })}
          </g>

          {/* Center Display */}
          <foreignObject x="45" y="45" width="110" height="110">
            <div
              style={{
                width: '100%',
                height: '100%',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                textAlign: 'center',
                pointerEvents: 'none',
              }}
            >
              <div
                style={{
                  fontSize: activeSlice ? '28px' : '32px',
                  fontWeight: 800,
                  color: activeSlice ? activeSlice.color : 'var(--text-primary)',
                  letterSpacing: '-0.03em',
                  lineHeight: 1,
                  transition: 'color 200ms ease, font-size 200ms ease',
                }}
              >
                {activeSlice ? activeSlice.value : total}
              </div>
              <div
                style={{
                  fontSize: '10px',
                  fontWeight: 600,
                  color: 'var(--text-muted)',
                  textTransform: 'uppercase',
                  letterSpacing: '0.08em',
                  marginTop: '5px',
                }}
              >
                {activeSlice ? activeSlice.name : 'Monitored'}
              </div>
              {activeSlice && (
                <div
                  style={{
                    fontSize: '11px',
                    fontWeight: 700,
                    color: activeSlice.color,
                    marginTop: '2px',
                    fontFamily: 'var(--font-mono)',
                  }}
                >
                  {activeSlice.percentage}%
                </div>
              )}
            </div>
          </foreignObject>
        </svg>
      </div>

      {/* Tier Badges Legend (Mastercard Satellite Pills) */}
      <div className="tier-legend-grid">
        {slices.map((slice) => {
          const isHovered = hoveredTier === slice.key;

          return (
            <button
              key={slice.key}
              type="button"
              className={`tier-legend-item ${isHovered ? 'hovered' : ''}`}
              onMouseEnter={() => setHoveredTier(slice.key)}
              onMouseLeave={() => setHoveredTier(null)}
              onClick={() => onSelectTier && onSelectTier(slice.key.toUpperCase())}
              style={{
                background: isHovered ? slice.bgSoft : 'rgba(255, 255, 255, 0.03)',
                borderColor: isHovered ? slice.color : 'rgba(255, 255, 255, 0.07)',
              }}
            >
              <div className="flex items-center gap-2">
                <span
                  className="tier-legend-dot"
                  style={{
                    backgroundColor: slice.color,
                    boxShadow: `0 0 8px ${slice.glow}`,
                  }}
                />
                <span className="tier-legend-label">{slice.name}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="tier-legend-count" style={{ color: slice.value > 0 ? slice.color : 'var(--text-muted)' }}>
                  {slice.value}
                </span>
                <span className="tier-legend-percent">
                  {slice.percentage}%
                </span>
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}
