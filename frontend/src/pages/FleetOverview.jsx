import usePolling from '../hooks/usePolling';
import { useState, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import Icon from '../components/Icon';
import TierBreakdownDonut from '../components/TierBreakdownDonut';
import HostRow from '../components/HostRow';
import Notice from '../components/Notice';
import { getHosts, getSessions, getComplianceSummary } from '../api/client';
import { getBarColor } from '../utils/colors';
import { summarizeTelemetry, filterHosts, riskValue } from '../utils/telemetry';

const TRANSPORT = [
  ['modern', 'TLS 1.3', 'var(--sev-clean)'],
  ['tls12', 'TLS 1.2', 'var(--sev-low)'],
  ['legacy', 'Legacy TLS', 'var(--sev-high)'],
  ['plaintext', 'Observed plaintext', 'var(--sev-critical)'],
  ['unknown', 'Unknown version or transport', 'var(--sev-info)'],
];

export default function FleetOverview() {
  const [hosts, setHosts] = useState([]);
  const [sessions, setSessions] = useState([]);
  const [compliance, setCompliance] = useState(null);
  const [loading, setLoading] = useState(true);
  const [errors, setErrors] = useState([]);
  const [available, setAvailable] = useState({ hosts: false, sessions: false });
  const [updated, setUpdated] = useState(null);
  const [search, setSearch] = useState('');
  const [tier, setTier] = useState('ALL');
  const [chartView, setChartView] = useState('donut');
  const requestId = useRef(0);
  const fetchTelemetry = async () => {
    const id = ++requestId.current;

    const results = await Promise.allSettled([getHosts(), getSessions(200), getComplianceSummary()]);
    if (id !== requestId.current) return;
    const [hostResult, sessionResult, complianceResult] = results;
    setAvailable({ hosts: hostResult.status === 'fulfilled', sessions: sessionResult.status === 'fulfilled' });
    if (hostResult.status === 'fulfilled') setHosts([...hostResult.value].sort((a, b) => (riskValue(b.aggregate_risk_score) ?? -1) - (riskValue(a.aggregate_risk_score) ?? -1)));
    if (sessionResult.status === 'fulfilled') setSessions(sessionResult.value);
    if (complianceResult.status === 'fulfilled') setCompliance(complianceResult.value);
    setErrors(results.flatMap((result, index) => result.status === 'rejected' ? [`Could not load ${['hosts', 'recent sessions', 'compliance'][index]}. ${result.reason?.message || 'Check the API connection and try again.'}`] : []));
    if (results.every(result => result.status === 'fulfilled')) setUpdated(new Date());
    setLoading(false);
  };
  useEffect(() => { fetchTelemetry(); return () => { requestId.current += 1; }; }, []);
  usePolling(fetchTelemetry);
  const summary = summarizeTelemetry(hosts, sessions);
  const filtered = filterHosts(hosts, search, tier);
  const ranked = hosts.filter(host => riskValue(host.aggregate_risk_score) !== null).slice(0, 10);
  const clearFilters = () => { setSearch(''); setTier('ALL'); };
  const display = value => loading || value == null ? '—' : value;

  return <div className="fleet-page">
    <header className="page-header fleet-heading"><div><h1 className="page-title">Fleet overview</h1><p className="page-subtitle">See risk at a glance. Select a host to investigate.</p></div><div className="ui-toolbar"><button type="button" className="btn btn-outline" disabled={loading} onClick={fetchTelemetry}><Icon name="refresh" size={15} />{loading ? 'Refreshing…' : 'Refresh'}</button><Link className="btn btn-primary" to="/dashboard/ingest"><Icon name="upload" size={15} />Import capture</Link></div></header>
    {errors.length > 0 && <Notice onRetry={loading ? undefined : fetchTelemetry}>{errors.join(' ')}</Notice>}
    <div className="fleet-updated" role="status">{loading ? 'Loading fleet telemetry…' : updated ? `Last successful refresh ${updated.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}` : 'Telemetry not loaded'}</div>
    <section className="fleet-metrics" aria-label="Fleet summary" aria-busy={loading}>
      {[
        ['Monitored hosts', available.hosts ? summary.hosts : null, ''],
        ['Captured sessions', available.hosts ? summary.totalSessions : null, ''],
        ['Average host risk', summary.averageRisk == null ? null : Math.round(summary.averageRisk), 'Out of 100 · lower is better'],
        ['Critical hosts', available.hosts ? summary.critical : null, 'Score ≥ 75'],
      ].map(([label, value, detail]) => <div className="fleet-metric" key={label}><h2>{label}</h2><strong>{display(value)}</strong>{detail && <p>{detail}</p>}</div>)}
    </section>
    <div className="fleet-analysis-grid">
      <section className="card fleet-chart" aria-labelledby="risk-chart-title"><div className="fleet-panel-heading"><div><h2 id="risk-chart-title">Risk breakdown</h2></div><div className="ui-segmented" aria-label="Risk display">{['donut', 'chart', 'table'].map(view => <button type="button" key={view} aria-pressed={view === chartView} onClick={() => setChartView(view)}>{view === 'donut' ? 'Overview' : view === 'chart' ? 'Ranked' : 'Table'}</button>)}</div></div>
        {loading ? <div className="ui-loading" role="status">Loading host risk…</div> : !hosts.length ? <div className="ui-empty"><h3>{available.hosts ? 'No scored hosts yet' : 'Host risk is unavailable'}</h3><p>{available.hosts ? 'Import a packet capture to start comparing host risk.' : 'Try refreshing after the API connection is restored.'}</p>{available.hosts && <Link className="btn btn-outline" to="/dashboard/ingest">Import capture</Link>}</div> : chartView === 'donut' ? <TierBreakdownDonut counts={summary.riskTiers} selectedTier={tier} onSelectTier={setTier} /> : chartView === 'chart' ? <div className="risk-chart"><div className="risk-chart-scale" aria-hidden="true"><span>0</span><span>25</span><span>50</span><span>75</span><span>100</span></div><ol>{ranked.map(host => <li key={host.host_id}><Link to={`/dashboard/sessions/${host.host_id}`} aria-label={`${host.ip}, risk ${Math.round(host.aggregate_risk_score)} out of 100. Inspect sessions.`}><span className="risk-chart-host">{host.ip}</span><span className="risk-chart-track" aria-hidden="true"><span style={{ width: `${riskValue(host.aggregate_risk_score)}%`, background: getBarColor(host.aggregate_risk_score) }} /></span><strong>{Math.round(host.aggregate_risk_score)}</strong></Link></li>)}</ol><p className="chart-caption">Top 10 scored hosts · risk out of 100.</p></div> : <div className="ui-table-scroll"><table className="ui-table"><thead><tr><th>Host</th><th>Risk / 100</th><th>Sessions</th></tr></thead><tbody>{ranked.map(host => <tr key={host.host_id}><td><Link to={`/dashboard/sessions/${host.host_id}`}>{host.ip}</Link></td><td>{Math.round(host.aggregate_risk_score)}</td><td>{host.session_count}</td></tr>)}</tbody></table></div>}
      </section>
      <section className="card" aria-labelledby="transport-title"><div className="fleet-panel-heading"><div><h2 id="transport-title">Transport security</h2><p>{sessions.length ? `Based on the latest ${sessions.length} sessions` : 'Recent session sample'}</p></div></div>
        {loading ? <div className="ui-loading" role="status">Loading transport data…</div> : !sessions.length ? <div className="ui-empty"><h3>{available.sessions ? 'No sessions to evaluate' : 'Transport data is unavailable'}</h3><p>Encryption is shown only when session evidence is available.</p></div> : <><div className="transport-summary"><strong>{summary.encryptedPercent}%</strong><span>confirmed encrypted<br /><small>Of the recent session sample</small></span></div><div className="transport-stack" aria-hidden="true">{TRANSPORT.map(([key, , color]) => <span key={key} style={{ width: `${summary.transport[key] / sessions.length * 100}%`, background: color }} />)}</div><dl className="transport-legend">{TRANSPORT.map(([key, label, color]) => <div key={key}><dt><i style={{ background: color }} />{label}</dt><dd>{summary.transport[key]} <span>{Math.round(summary.transport[key] / sessions.length * 100)}%</span></dd></div>)}</dl></>}
        <div className="fleet-panel-footer"><span>{compliance?.overall_status ? `Compliance: ${compliance.overall_status}` : 'Compliance details in rule explorer'}</span><Link to="/dashboard/rules">View compliance <span aria-hidden="true">→</span></Link></div>
      </section>
    </div>
    <section className="card" aria-labelledby="inventory-title"><div className="fleet-panel-heading"><div><h2 id="inventory-title">Host inventory <span className="ui-count">{filtered.length}</span></h2></div></div><div className="fleet-filters"><label className="ui-search"><Icon name="search" size={16} /><input type="search" placeholder="Search hostname or IP…" aria-label="Search hostname or IP" value={search} onChange={event => setSearch(event.target.value)} /></label><div className="ui-filter-group" aria-label="Filter by risk tier">{['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'CLEAN', ...(summary.riskTiers.unknown ? ['UNKNOWN'] : [])].map(value => <button className="btn btn-outline" type="button" aria-pressed={tier === value} key={value} onClick={() => setTier(value)}>{value === 'CLEAN' ? 'Low risk' : value[0] + value.slice(1).toLowerCase()}</button>)}</div></div>
      {loading ? <div className="ui-loading" role="status">Loading host inventory…</div> : filtered.length ? <div className="host-inventory">{filtered.map(host => <HostRow host={host} key={host.host_id} />)}</div> : <div className="ui-empty"><h3>{search || tier !== 'ALL' ? 'No matching hosts' : available.hosts ? 'Your inventory starts here' : 'Host inventory is unavailable'}</h3><p>{search || tier !== 'ALL' ? 'Try another hostname or clear the active filters.' : available.hosts ? 'Import a capture or send a test message from the dispatcher.' : 'Check the API connection, then refresh.'}</p>{search || tier !== 'ALL' ? <button className="btn btn-outline" onClick={clearFilters}>Clear filters</button> : available.hosts ? <Link className="btn btn-primary" to="/dashboard/ingest">Import a capture</Link> : <button className="btn btn-outline" onClick={fetchTelemetry}>Try again</button>}</div>}
    </section>
  </div>;
}
