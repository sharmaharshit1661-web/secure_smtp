import { useEffect, useRef, useState } from 'react';
import Icon from './Icon';

function useCountUp(target, duration = 1000) {
  const isReduced = typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const [value, setValue] = useState(() => (isReduced || typeof target !== 'number' ? target : 0));
  const rafRef = useRef(null);

  useEffect(() => {
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduce || typeof target !== 'number') {
      return undefined;
    }
    const start = performance.now();
    const from = 0;
    function animate(now) {
      const elapsed = now - start;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setValue(from + (target - from) * eased);
      if (progress < 1) rafRef.current = requestAnimationFrame(animate);
    }
    rafRef.current = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(rafRef.current);
  }, [target, duration]);

  if (isReduced || typeof target !== 'number') {
    return target;
  }

  return value;
}

export default function KpiCard({ label, value, sub, icon, accentColor, className = '', delay = 0 }) {
  const numeric = typeof value === 'number' ? value : parseFloat(value);
  const isNumeric = !Number.isNaN(numeric) && (typeof value === 'number' || /^\d+(\.\d+)?$/.test(String(value)));
  const animated = useCountUp(isNumeric ? numeric : 0);
  const display = isNumeric
    ? (Number.isInteger(numeric) ? Math.round(animated) : animated.toFixed(1))
    : value;

  return (
    <div
      className={`kpi-card animate-in animate-in-${delay + 1} ${className}`}
      style={{ '--kpi-accent': accentColor }}
    >
      <div className="kpi-top">
        <span className="kpi-label">{label}</span>
        {icon && (
          <span className="kpi-icon" style={accentColor ? { borderColor: accentColor, color: accentColor, background: `${accentColor}12` } : undefined}>
            <Icon name={icon} size={16} />
          </span>
        )}
      </div>
      <div className="kpi-value" style={accentColor ? { color: accentColor } : undefined}>
        {display}
      </div>
      {sub && <div className="kpi-sub">{sub}</div>}
    </div>
  );
}