import { Link } from 'react-router-dom';
import SeverityBadge from './SeverityBadge';
import { getTierFromScore, getTierColorRaw } from '../utils/colors';
import { riskValue } from '../utils/telemetry';

export default function HostRow({ host }) {
  const score = riskValue(host.aggregate_risk_score);
  const tier = score == null ? 'info' : getTierFromScore(score);
  const color = getTierColorRaw(tier);
  return <Link className="host-row" to={`/dashboard/sessions/${host.host_id}`} aria-label={`Inspect ${host.ip}, ${host.session_count} sessions, ${score == null ? 'risk unavailable' : `risk ${Math.round(score)} out of 100`}`}>
    <div className="host-row-left"><span className="host-risk-indicator" style={{ background: color }} /><div><div className="host-ip">{host.ip}</div><div className="host-meta">{host.session_count} sessions analyzed</div></div></div>
    <div className="host-row-right"><div className="host-score" style={{ color }}>{score == null ? '—' : Math.round(score)}<span className="host-score-denominator">/100</span></div><SeverityBadge severity={tier} /><span className="host-inspect">Inspect <span aria-hidden="true">→</span></span></div>
  </Link>;
}
