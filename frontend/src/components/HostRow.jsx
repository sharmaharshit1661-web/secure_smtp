import { useNavigate } from 'react-router-dom';
import SeverityBadge from './SeverityBadge';
import { getTierFromScore, getTierColorRaw } from '../utils/colors';
import { formatScore } from '../utils/format';

export default function HostRow({ host }) {
  const navigate = useNavigate();
  const score = host.aggregate_risk_score || 0;
  const tier = getTierFromScore(score);
  const color = getTierColorRaw(tier);

  return (
    <div className="host-row" onClick={() => navigate(`/sessions/${host.host_id}`)}>
      <div className="host-row-left">
        <div className="host-risk-bar" style={{ background: color, boxShadow: `0 0 8px ${color}` }} />
        <div>
          <div className="host-ip">{host.ip}</div>
          <div className="host-meta">{host.session_count} sessions analyzed</div>
        </div>
      </div>
      <div className="host-row-right">
        <div className="host-score" style={{ color }}>
          {formatScore(score)}<span className="host-score-denominator">/100</span>
        </div>
        <SeverityBadge severity={tier === 'clean' ? 'clean' : tier} />
        <button className="btn btn-sm btn-outline">Inspect →</button>
      </div>
    </div>
  );
}
