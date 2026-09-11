const CONFIG = {
  critical: { label: 'CRITICAL', isAlert: true },
  high: { label: 'HIGH', isAlert: true },
  medium: { label: 'MEDIUM', isAlert: false },
  low: { label: 'LOW', isAlert: false },
  clean: { label: 'HEALTHY', isAlert: false },
  healthy: { label: 'HEALTHY', isAlert: false },
  info: { label: 'INFO', isAlert: false },
};

export default function SeverityBadge({ severity }) {
  const sev = String(severity || 'info').toLowerCase();
  const cfg = CONFIG[sev] || { label: sev.toUpperCase(), isAlert: false };

  return (
    <span className={`badge badge-${sev}`}>
      <span className={`badge-indicator ${cfg.isAlert ? 'badge-indicator-pulse' : ''}`} />
      <span>{cfg.label}</span>
    </span>
  );
}
