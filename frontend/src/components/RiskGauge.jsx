import { useEffect, useRef, useState } from 'react';
import { getTierColor } from '../utils/colors';

export default function RiskGauge({ score = 0, tier = 'clean', size = 150 }) {
  const isReduced = typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const [animatedScore, setAnimatedScore] = useState(() => (isReduced ? score : 0));
  const rafRef = useRef(null);

  useEffect(() => {
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduce) {
      return undefined;
    }
    const start = performance.now();
    const duration = 900;
    const from = 0;
    const to = score;

    function animate(now) {
      const elapsed = now - start;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setAnimatedScore(from + (to - from) * eased);
      if (progress < 1) rafRef.current = requestAnimationFrame(animate);
    }

    rafRef.current = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(rafRef.current);
  }, [score]);

  const effectiveScore = isReduced ? score : animatedScore;

  const color = getTierColor(tier);
  const radius = (size - 20) / 2;
  const cx = size / 2;
  const cy = size / 2;
  const circumference = Math.PI * radius;
  const strokeDash = (effectiveScore / 100) * circumference;
  const gradId = `gauge-grad-${tier}`;

  const ticks = Array.from({ length: 21 }, (_, i) => {
    const angle = Math.PI + (i / 20) * Math.PI;
    const isMajor = i % 5 === 0;
    const innerR = radius - (isMajor ? 12 : 8);
    const outerR = radius - 2;
    return (
      <line
        key={i}
        x1={cx + innerR * Math.cos(angle)}
        y1={cy + innerR * Math.sin(angle)}
        x2={cx + outerR * Math.cos(angle)}
        y2={cy + outerR * Math.sin(angle)}
        stroke={isMajor ? 'rgba(255,255,255,0.18)' : 'rgba(255,255,255,0.06)'}
        strokeWidth={isMajor ? 1.5 : 0.8}
        strokeLinecap="round"
      />
    );
  });

  return (
    <svg width={size} height={size * 0.66} viewBox={`0 0 ${size} ${size * 0.66}`}>
      <defs>
        <linearGradient id={gradId} x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor={color} stopOpacity="0.55" />
          <stop offset="100%" stopColor={color} stopOpacity="1" />
        </linearGradient>
      </defs>
      {ticks}
      {/* Background arc */}
      <path
        d={`M ${cx - radius} ${cy} A ${radius} ${radius} 0 0 1 ${cx + radius} ${cy}`}
        fill="none"
        stroke="rgba(255,255,255,0.05)"
        strokeWidth={7}
        strokeLinecap="round"
      />
      {/* Value arc */}
      <path
        d={`M ${cx - radius} ${cy} A ${radius} ${radius} 0 0 1 ${cx + radius} ${cy}`}
        fill="none"
        stroke={`url(#${gradId})`}
        strokeWidth={7}
        strokeLinecap="round"
        strokeDasharray={`${strokeDash} ${circumference}`}
        style={{ filter: `drop-shadow(0 0 7px ${color}66)`, transition: 'stroke-dasharray 80ms linear' }}
      />
      {/* Score text */}
      <text x={cx} y={cy - 10} textAnchor="middle" fill="var(--text-primary)"
        fontFamily="var(--font-mono)" fontSize={size * 0.2} fontWeight="700"
        style={{ letterSpacing: '-0.03em' }}>
        {Math.round(effectiveScore)}
      </text>
      <text x={cx} y={cy + 10} textAnchor="middle" fill="var(--text-muted)"
        fontFamily="var(--font-mono)" fontSize={size * 0.075} letterSpacing="0.12em">
        / 100
      </text>
    </svg>
  );
}
