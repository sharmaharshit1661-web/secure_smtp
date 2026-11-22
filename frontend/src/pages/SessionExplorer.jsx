import Notice from '../components/Notice';
import useClipboard from '../hooks/useClipboard';
import { useState, useEffect, useCallback, useRef } from 'react';
import { useParams, useNavigate, useSearchParams } from 'react-router-dom';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell
} from 'recharts';
import RiskGauge from '../components/RiskGauge';
import WireDiagram from '../components/WireDiagram';
import FindingCard from '../components/FindingCard';
import CertChain from '../components/CertChain';
import SeverityBadge from '../components/SeverityBadge';
import Icon from '../components/Icon';
import {
  getHosts,
  getHostDetail,
  getSessionDetail,
  getCopilotRemediation,
  getCopilotBriefing,
  askCopilot,
} from '../api/client';
import { riskValue } from '../utils/telemetry';
import { getTierColorRaw } from '../utils/colors';
import { trackRemediation } from '../api/client';

const TOOLTIP_STYLE = {
  backgroundColor: 'var(--bg-surface)',
  border: '1px solid var(--border)',
  borderRadius: '10px',
  color: 'var(--text-primary)',
  fontFamily: 'var(--font-mono)',
  fontSize: '12px',
  boxShadow: 'var(--shadow-md)',
};

export default function SessionExplorer() {
  const { copyText, clipboardError } = useClipboard();
  const { hostId: routeHostId } = useParams();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const requestedSession = Number(searchParams.get('session'));

  const [hosts, setHosts] = useState([]);
  const [selectedHostId, setSelectedHostId] = useState(routeHostId ? Number(routeHostId) : null);
  const [hostSessions, setHostSessions] = useState([]);
  const [selectedSessionId, setSelectedSessionId] = useState(null);
  const [sessionData, setSessionData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [sessionLoading, setSessionLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('findings');
  const [serverType, setServerType] = useState('postfix');
  const [remediationData, setRemediationData] = useState(null);
  const [remediationLoading, setRemediationLoading] = useState(false);
  const [briefingData, setBriefingData] = useState(null);
  const [briefingLoading, setBriefingLoading] = useState(false);
  const [copilotQuery, setCopilotQuery] = useState('');
  const [copilotAnswer, setCopilotAnswer] = useState(null);
  const [copilotEngine, setCopilotEngine] = useState('');
  const [copilotLoading, setCopilotLoading] = useState(false);
  const [copiedConfig, setCopiedConfig] = useState(false);
  const [copiedMemo, setCopiedMemo] = useState(false);

  const [tracked, setTracked] = useState({});
  const [error, setError] = useState('');
  const [hostsLoading, setHostsLoading] = useState(true);
  const [retryKey, setRetryKey] = useState(0);
  const actionIds = useRef({ remediation: 0, briefing: 0, copilot: 0 });
  useEffect(() => {
    for (const key of Object.keys(actionIds.current)) actionIds.current[key] += 1;
    setRemediationData(null); setBriefingData(null); setCopilotAnswer(null);
    setRemediationLoading(false); setBriefingLoading(false); setCopilotLoading(false);
    setCopiedConfig(false); setCopiedMemo(false);
  }, [selectedSessionId]);

  useEffect(() => {
    actionIds.current.remediation += 1;
    setRemediationData(null); setRemediationLoading(false); setCopiedConfig(false);
  }, [serverType]);

  const handleFetchRemediation = useCallback(async (type = serverType) => {
    if (!selectedSessionId) return;
    const id = ++actionIds.current.remediation;
    setRemediationLoading(true); setError(''); setRemediationData(null);
    try {
      const result = await getCopilotRemediation(selectedSessionId, type);
      if (id === actionIds.current.remediation) setRemediationData(result);
    } catch (err) {
      if (id === actionIds.current.remediation) setError(`Could not generate configuration. ${err.message}`);
    } finally { if (id === actionIds.current.remediation) setRemediationLoading(false); }
  }, [selectedSessionId, serverType]);
  const handleFetchBriefing = useCallback(async () => {
    if (!selectedSessionId) return;
    const id = ++actionIds.current.briefing;
    setBriefingLoading(true); setError('');
    try {
      const result = await getCopilotBriefing(selectedSessionId);
      if (id === actionIds.current.briefing) setBriefingData(result);
    } catch (err) {
      if (id === actionIds.current.briefing) setError(`Could not generate briefing. ${err.message}`);
    } finally { if (id === actionIds.current.briefing) setBriefingLoading(false); }
  }, [selectedSessionId]);
  const handleAskCopilot = async (queryText) => {
    const query = (queryText || copilotQuery).trim();
    if (!selectedSessionId || !query || copilotLoading) return;
    const id = ++actionIds.current.copilot;
    setCopilotLoading(true); setError('');
    try {
      const result = await askCopilot(selectedSessionId, query);
      if (id === actionIds.current.copilot) { setCopilotAnswer(result.answer); setCopilotEngine(result.engine); }
    } catch (err) {
      if (id === actionIds.current.copilot) setError(`Could not answer your question. ${err.message}`);
    } finally { if (id === actionIds.current.copilot) setCopilotLoading(false); }
  };

  useEffect(() => {
    let cancelled = false;
    setHostsLoading(true); setError('');
    Promise.all([getHosts(), requestedSession && !routeHostId ? getSessionDetail(requestedSession) : null]).then(([data, requested]) => {
      if (cancelled) return;
      const sorted = [...data].sort((a, b) => (b.aggregate_risk_score || 0) - (a.aggregate_risk_score || 0));
      setHosts(sorted);
      setSelectedHostId(routeHostId ? Number(routeHostId) : requested?.host_id ?? sorted[0]?.host_id ?? null);
    }).catch(err => { if (!cancelled) { setHosts([]); setError(`Could not load hosts. ${err.message}`); } })
      .finally(() => { if (!cancelled) setHostsLoading(false); });
    return () => { cancelled = true; };
  }, [routeHostId, requestedSession, retryKey]);
  useEffect(() => {
    let cancelled = false;
    setHostSessions([]); setSelectedSessionId(null); setSessionData(null);
    if (!selectedHostId) { setLoading(false); return; }
    setLoading(true);
    getHostDetail(selectedHostId).then(detail => {
      if (cancelled) return;
      const list = detail?.sessions || [];
      setHostSessions(list); setSelectedSessionId(list.find(session => session.session_id === requestedSession)?.session_id ?? list[0]?.session_id ?? null);
    }).catch(err => { if (!cancelled) setError(`Could not load this host. ${err.message}`); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [selectedHostId, requestedSession, retryKey]);
  useEffect(() => {
    let cancelled = false;
    setSessionData(null);
    if (!selectedSessionId) { setSessionLoading(false); return; }
    setSessionLoading(true);
    getSessionDetail(selectedSessionId).then(detail => { if (!cancelled) setSessionData(detail); })
      .catch(err => { if (!cancelled) setError(`Could not load this session. ${err.message}`); })
      .finally(() => { if (!cancelled) setSessionLoading(false); });
    return () => { cancelled = true; };
  }, [selectedSessionId, retryKey]);
  const handleHostChange = event => {
    const id = Number(event.target.value);
    setError(''); setSelectedHostId(id); navigate(`/dashboard/sessions/${id}`);
  };

  const hs = sessionData?.handshake;
  const riskScore = riskValue(sessionData?.risk_score?.score);
  const riskTier = sessionData?.risk_score?.tier ?? 'info';
  const anomaly = sessionData?.anomaly_score;
  const findings = sessionData?.findings || [];
  const certs = sessionData?.certificates || [];

  // Parse SHAP / AI Explanation
  let explanation = sessionData?.risk_score?.explanation;
  if (typeof explanation === 'string') {
    try {
      explanation = JSON.parse(explanation);
    } catch {
      explanation = {};
    }
  }

  const contributions = (explanation?.contributions || []).map((c) => ({
    name: c.rule_id,
    percentage: Math.round(c.percentage || 0),
    severity: c.severity || 'info',
    color: getTierColorRaw(c.severity || 'info'),
  }));

  const shapValues = explanation?.shap_values || {};
  const shapChartData = Object.entries(shapValues)
    .sort((a, b) => Math.abs(b[1]) - Math.abs(a[1]))
    .slice(0, 8)
    .map(([feature, val]) => ({
      feature,
      impact: Number(Number(val).toFixed(3)),
      color: val > 0 ? getTierColorRaw('critical') : getTierColorRaw('clean'),
    }));

  return (
    <div className="flex flex-col gap-5">
      {clipboardError && <Notice>{clipboardError}</Notice>}
      {error && <Notice onRetry={() => setRetryKey(key => key + 1)}>{error}</Notice>}
      {/* Title & Selectors */}
      <div className="page-header animate-in">
        <div>
          <h1 className="page-title">
            <span className="page-title-icon"><Icon name="microscope" size={24} /></span>
            Session Explorer
          </h1>
          <p className="page-subtitle">
            Select a session to review its risks and evidence.
          </p>
        </div>
      </div>

      {/* Selectors Bar */}
      <div className="card animate-in animate-in-1" style={{ padding: '16px 20px' }}>
        <div className="grid grid-1-2 gap-4 items-center">
          <div>
            <label className="field-label" htmlFor="session-host">Monitored host</label>
            <select
              className="select"
              id="session-host"
              value={selectedHostId || ''}
              onChange={handleHostChange}
              disabled={hosts.length === 0}
            >
              {!hosts.length && <option value="">{hostsLoading ? 'Loading hosts…' : 'No hosts available'}</option>}
              {hosts.map((h) => (
                <option key={h.host_id} value={h.host_id}>
                  {h.ip} — Risk {riskValue(h.aggregate_risk_score) == null ? 'unknown' : Math.round(h.aggregate_risk_score)} ({h.session_count} sessions)
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="field-label" htmlFor="session-stream">Captured session</label>
            <select
              className="select"
              id="session-stream"
              value={selectedSessionId || ''}
              onChange={(e) => setSelectedSessionId(Number(e.target.value))}
              disabled={hostSessions.length === 0}
            >
              {!hostSessions.length && <option value="">{loading ? 'Loading sessions…' : 'No sessions available'}</option>}
              {hostSessions.map((s) => (
                <option key={s.session_id} value={s.session_id}>
                  Session #{s.session_id} | {s.src_ip}:{s.src_port} → {s.dst_ip}:{s.dst_port} [{s.protocol?.toUpperCase()}] — Risk {s.risk_score == null ? 'unknown' : Math.round(s.risk_score)}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Loading & Empty States */}
      {hostsLoading || loading || sessionLoading ? (
        <div className="flex flex-col gap-3">
          <div className="skeleton" style={{ height: '90px' }} />
          <div className="skeleton" style={{ height: '180px' }} />
          <div className="skeleton" style={{ height: '300px' }} />
        </div>
      ) : !sessionData ? (
        <div className="empty-state">
          <div className="empty-state-icon"><Icon name="search" size={24} /></div>
          <div className="font-bold text-md text-primary" style={{ marginBottom: 'var(--space-1)' }}>
            No Session Stream Selected
          </div>
          <p className="text-secondary text-sm" style={{ maxWidth: '420px', margin: '0 auto' }}>
            Select a target host and session from the controls above or ingest a PCAP file to explore cryptographic telemetry.
          </p>
        </div>
      ) : (
        <>
          {/* Wire Diagram */}
          <div className="animate-in animate-in-2">
            <WireDiagram session={sessionData} />
          </div>

          <section className="session-summary" aria-label="Session summary">
            <div className="session-risk"><RiskGauge score={riskScore} tier={riskTier} size={120} /><SeverityBadge severity={riskTier} /></div>
            <dl className="session-facts">
              <div><dt>Findings</dt><dd>{findings.length}</dd></div>
              <div><dt>TLS version</dt><dd>{hs?.tls_version_negotiated || 'Not observed'}</dd></div>
              <div><dt>Anomaly</dt><dd>{anomaly ? anomaly.is_anomalous ? 'Detected' : 'Not detected' : 'Not assessed'}</dd></div>
            </dl>
          </section>

          {/* Deep Tabs */}
          <div className="card animate-in animate-in-4" style={{ padding: 'var(--space-5)' }}>
            <div className="tabs" role="group" aria-label="Session details">
              <button
                className={`tab ${activeTab === 'findings' ? 'active' : ''}`}
                aria-pressed={activeTab === 'findings'}
                onClick={() => setActiveTab('findings')}
              >
                <Icon name="alert" size={14} /> Findings ({findings.length})
              </button>
              <button
                className={`tab ${activeTab === 'handshake' ? 'active' : ''}`}
                aria-pressed={activeTab === 'handshake'}
                onClick={() => setActiveTab('handshake')}
              >
                <Icon name="lock" size={14} /> Handshake
              </button>
              <button
                className={`tab ${activeTab === 'certs' ? 'active' : ''}`}
                aria-pressed={activeTab === 'certs'}
                onClick={() => setActiveTab('certs')}
              >
                <Icon name="certificate" size={14} /> Certificate Chain ({certs.length})
              </button>
              <button
                className={`tab ${activeTab === 'shap' ? 'active' : ''}`}
                aria-pressed={activeTab === 'shap'}
                onClick={() => setActiveTab('shap')}
              >
                <Icon name="chart" size={14} /> Risk drivers
              </button>
              <button
                className={`tab ${activeTab === 'copilot' ? 'active' : ''}`}
                aria-pressed={activeTab === 'copilot'}
                onClick={() => setActiveTab('copilot')}
              >
                <Icon name="sparkle" size={14} /> AI guidance
              </button>
            </div>

            {/* Tab 1: Handshake */}
            {activeTab === 'handshake' && (
              hs ? (
                <div className="grid grid-2 gap-5">
                  <div>
                    <div className="font-bold text-md text-primary" style={{ marginBottom: 'var(--space-3)' }}>
                      Handshake Parameters
                    </div>
                    <div className="flex flex-col gap-2">
                      <div className="info-grid">
                        <div>
                          <div className="info-item-label">Negotiated TLS Version</div>
                          <div className="info-item-value text-accent">{hs.tls_version_negotiated || 'N/A'}</div>
                        </div>
                        <div>
                          <div className="info-item-label">Cipher Suite</div>
                          <div className="info-item-value">{hs.cipher_suite_negotiated || 'N/A'}</div>
                        </div>
                        <div>
                          <div className="info-item-label">Key Exchange Type</div>
                          <div className="info-item-value">{String(hs.key_exchange_type || 'N/A').toUpperCase()}</div>
                        </div>
                        <div>
                          <div className="info-item-label">Forward Secrecy</div>
                          <div className="info-item-value">{hs.forward_secrecy == null ? 'Unknown' : hs.forward_secrecy ? 'Supported' : 'Not observed'}</div>
                        </div>
                      </div>
                      {hs.visibility_limited && (
                        <div className="finding-remediation" style={{ marginTop: 'var(--space-3)' }}>
                          <Icon name="info" size={14} />
                          <div><strong>TLS 1.3 Limited Visibility:</strong> Extensions post-ServerHello are shielded passively by design.</div>
                        </div>
                      )}
                    </div>
                  </div>

                  <div>
                    <div className="font-bold text-md text-primary" style={{ marginBottom: 'var(--space-3)' }}>
                      Cryptographic Fingerprints
                    </div>
                    <div className="flex flex-col gap-3">
                      {hs.ja3 && (
                        <div>
                          <div className="info-item-label">JA3 (Client Fingerprint)</div>
                          <code className="text-mono text-xs text-accent" style={{ wordBreak: 'break-all' }}>{hs.ja3}</code>
                        </div>
                      )}
                      {hs.ja3s && (
                        <div>
                          <div className="info-item-label">JA3S (Server Fingerprint)</div>
                          <code className="text-mono text-xs text-secondary" style={{ wordBreak: 'break-all' }}>{hs.ja3s}</code>
                        </div>
                      )}
                      {hs.ja4 && (
                        <div>
                          <div className="info-item-label">JA4 (Modern High-Assurance Fingerprint)</div>
                          <code className="text-mono text-xs text-clean" style={{ wordBreak: 'break-all' }}>{hs.ja4}</code>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="empty-state">
                  <div className="empty-state-icon"><Icon name="alert" size={24} /></div>
                  <p>No TLS handshake data was captured for this session.</p>
                </div>
              )
            )}

            {/* Tab 2: Certificate Chain */}
            {activeTab === 'certs' && (
              <CertChain certificates={certs} />
            )}

            {/* Tab 3: Findings */}
            {activeTab === 'findings' && (
              findings.length > 0 ? (
                <div className="flex flex-col gap-1">
                  {findings.map((f, i) => (
                    <div key={i} className="animate-in" style={{ animationDelay: `${Math.min(i * 40, 240)}ms` }}>
                      <FindingCard finding={f} />
                      <button className="text-action" disabled={tracked[selectedSessionId + ':' + f.rule_id]} onClick={async () => {
                        try {
                          await trackRemediation(selectedSessionId, f.rule_id);
                          setTracked(previous => ({...previous, [selectedSessionId + ':' + f.rule_id]: true}));
                        } catch (err) { setError('Could not track finding. ' + err.message); }
                      }}>{tracked[selectedSessionId + ':' + f.rule_id] ? 'Tracked in Operations' : 'Track follow-up'}</button>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="empty-state">
                  <div className="empty-state-icon"><Icon name="check" size={24} /></div>
                  <div className="font-bold text-md text-primary">No findings recorded</div>
                  <p className="text-secondary text-sm">No findings are recorded for this session. Results depend on the traffic and handshake data available.</p>
                </div>
              )
            )}

            {/* Tab 4: Risk drivers */}
            {activeTab === 'shap' && (
              <div className="flex flex-col gap-5">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-sm text-secondary">Scoring Engine:</span>
                  <code className="text-mono text-accent text-sm font-bold">
                    {explanation?.method || 'Not reported'}
                  </code>
                </div>

                <div className="grid grid-2 gap-5">
                  {/* Vulnerability Feature Contributions */}
                  <div>
                    <div className="font-bold text-sm text-primary" style={{ marginBottom: 'var(--space-3)' }}>
                      Vulnerability Feature Contributions
                    </div>
                    {contributions.length > 0 ? (
                      <div style={{ height: 250, width: '100%' }}>
                        <ResponsiveContainer width="100%" height="100%">
                          <BarChart data={contributions} margin={{ top: 10, right: 10, left: -20, bottom: 25 }}>
                            <XAxis dataKey="name" stroke="var(--text-muted)" tick={{ fill: 'var(--text-secondary)', fontSize: 10, fontFamily: 'var(--font-mono)' }} angle={-20} textAnchor="end" />
                            <YAxis stroke="var(--text-muted)" tick={{ fill: 'var(--text-secondary)', fontSize: 10, fontFamily: 'var(--font-mono)' }} unit="%" />
                            <Tooltip
                              contentStyle={TOOLTIP_STYLE}
                              cursor={{ fill: 'rgba(255,255,255,0.04)' }}
                              formatter={(val) => [`${val}%`, 'Impact Contribution']}
                            />
                            <Bar isAnimationActive={false} dataKey="percentage" radius={[5, 5, 0, 0]} maxBarSize={34}>
                              {contributions.map((entry, index) => (
                                <Cell key={`contrib-${index}`} fill={entry.color} />
                              ))}
                            </Bar>
                          </BarChart>
                        </ResponsiveContainer>
                      </div>
                    ) : (
                      <div className="text-secondary text-sm">No vulnerability features active for this session.</div>
                    )}
                  </div>

                  {/* SHAP Feature Attribution Waterfall */}
                  <div>
                    <div className="font-bold text-sm text-primary" style={{ marginBottom: 'var(--space-3)' }}>
                      SHAP Feature Attribution (Impact on Risk)
                    </div>
                    {shapChartData.length > 0 ? (
                      <div style={{ height: 250, width: '100%' }}>
                        <ResponsiveContainer width="100%" height="100%">
                          <BarChart
                            layout="vertical"
                            data={shapChartData}
                            margin={{ top: 10, right: 20, left: 40, bottom: 5 }}
                          >
                            <XAxis type="number" stroke="var(--text-muted)" tick={{ fill: 'var(--text-secondary)', fontSize: 10, fontFamily: 'var(--font-mono)' }} />
                            <YAxis
                              type="category"
                              dataKey="feature"
                              stroke="var(--text-muted)"
                              tick={{ fill: 'var(--text-secondary)', fontSize: 10, fontFamily: 'var(--font-mono)' }}
                              width={110}
                            />
                            <Tooltip
                              contentStyle={TOOLTIP_STYLE}
                              cursor={{ fill: 'rgba(255,255,255,0.04)' }}
                              formatter={(val) => [val, 'SHAP Value']}
                            />
                            <Bar isAnimationActive={false} dataKey="impact" radius={[0, 5, 5, 0]} maxBarSize={16}>
                              {shapChartData.map((entry, index) => (
                                <Cell key={`shap-${index}`} fill={entry.color} />
                              ))}
                            </Bar>
                          </BarChart>
                        </ResponsiveContainer>
                      </div>
                    ) : (
                      <div className="text-secondary text-sm">No SHAP explanation vector available.</div>
                    )}
                  </div>
                </div>
                {(contributions.length > 0 || shapChartData.length > 0) && <details className="chart-data-details"><summary>View chart values</summary><div className="ui-table-scroll"><table className="ui-table"><caption>Risk attribution for this session</caption><thead><tr><th>Feature</th><th>Measure</th><th>Value</th></tr></thead><tbody>{contributions.map((row, index) => <tr key={`rule-${index}`}><td>{row.name}</td><td>Contribution</td><td>{row.percentage}%</td></tr>)}{shapChartData.map(row => <tr key={row.feature}><td>{row.feature}</td><td>SHAP impact</td><td>{row.impact > 0 ? '+' : ''}{row.impact}</td></tr>)}</tbody></table></div><p className="chart-caption">Positive SHAP values increase the model’s risk estimate; negative values decrease it.</p></details>}
              </div>
            )}

            {/* Tab 5: AI guidance */}
            {activeTab === 'copilot' && (
              <div className="flex flex-col gap-5">
                {/* Section 1: Server Configuration Directives */}
                <div
                  className="card"
                  style={{
                    borderColor: 'var(--border)',
                    background: 'var(--bg-inset)',
                  }}
                >
                  <div className="flex justify-between items-center" style={{ marginBottom: 'var(--space-3)' }}>
                    <div className="flex items-center gap-2">
                      <Icon name="code" size={18} />
                      <div>
                        <div className="font-bold text-md text-primary">Server configuration guidance</div>
                        <div className="text-secondary text-xs">Generate suggested settings for the selected session and review them before applying.</div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      <label className="text-secondary text-xs">Target Daemon:</label>
                      <select
                        className="select"
                        style={{ width: '190px', padding: '6px 10px', fontSize: '12px' }}
                        aria-label="Mail server software"
                        value={serverType}
                        onChange={(e) => setServerType(e.target.value)}
                      >
                        <option value="postfix">Postfix (main.cf)</option>
                        <option value="dovecot">Dovecot (10-ssl.conf)</option>
                        <option value="exchange">Microsoft Exchange (PowerShell)</option>
                        <option value="exim">Exim4 (exim4.conf)</option>
                        <option value="sendmail">Sendmail (sendmail.mc)</option>
                      </select>
                      <button
                        className="btn btn-primary btn-sm"
                        onClick={() => handleFetchRemediation(serverType)}
                        disabled={remediationLoading}
                      >
                        {remediationLoading ? 'Generating…' : 'Generate Fix'}
                      </button>
                    </div>
                  </div>

                  {remediationData ? (
                    <div className="flex flex-col gap-3">
                      <div className="flex justify-between items-center text-xs">
                        <span className="text-mono text-muted">
                          Target File: <strong className="text-accent">{remediationData.filepath}</strong>
                        </span>
                        <button
                          className="btn btn-outline btn-sm"
                          onClick={() => {
                            copyText(remediationData.config_content, () => {
                            setCopiedConfig(true);
                            setTimeout(() => setCopiedConfig(false), 2000);
                            });
                          }}
                        >
                          <Icon name="copy" size={13} />
                          {copiedConfig ? 'Copied Config!' : 'Copy Configuration'}
                        </button>
                      </div>

                      <pre
                        className="text-mono text-xs"
                        style={{
                          background: 'var(--bg-inset)',
                          padding: '14px',
                          borderRadius: '8px',
                          overflowX: 'auto',
                          maxHeight: '260px',
                          lineHeight: '1.5',
                          color: 'var(--text-primary)',
                          border: '1px solid var(--border-subtle)',
                        }}
                      >
                        {remediationData.config_content}
                      </pre>

                      {remediationData.commands && remediationData.commands.length > 0 && (
                        <div>
                          <div className="font-semibold text-xs text-secondary" style={{ marginBottom: '6px' }}>
                            Deployment &amp; Verification Commands:
                          </div>
                          <pre
                            className="text-mono text-xs"
                            style={{
                              background: 'var(--bg-inset)',
                              padding: '10px 14px',
                              borderRadius: '6px',
                              color: 'var(--accent)',
                              border: '1px solid var(--border-subtle)',
                            }}
                          >
                            {remediationData.commands.join('\n')}
                          </pre>
                        </div>
                      )}

                      {remediationData.resolved_findings && (
                        <div className="flex items-center gap-2" style={{ marginTop: '4px' }}>
                          <span className="text-xs text-muted">Remediates:</span>
                          <div className="flex gap-1 flex-wrap">
                            {remediationData.resolved_findings.map((fid) => (
                              <span key={fid} className="badge badge-clean" style={{ fontSize: '10px' }}>
                                ✓ {fid}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="text-secondary text-xs" style={{ padding: '12px 0' }}>
                      Select your mail server software above or click &quot;Generate Fix&quot; to synthesize configuration directives.
                    </div>
                  )}
                </div>

                {/* Section 2: Executive Incident Briefing Memo */}
                <div className="card">
                  <div className="flex justify-between items-center" style={{ marginBottom: 'var(--space-3)' }}>
                    <div className="flex items-center gap-2">
                      <span className="text-accent"><Icon name="file" size={16} /></span>
                      <div>
                        <div className="font-bold text-md text-primary">Executive CISO Incident Briefing</div>
                        <div className="text-secondary text-xs">Plain-English risk analysis, regulatory exposure, and threat vectors for leadership.</div>
                      </div>
                    </div>

                    <div className="flex gap-2">
                      <button
                        className="btn btn-outline btn-sm"
                        onClick={handleFetchBriefing}
                        disabled={briefingLoading}
                      >
                        {briefingLoading ? 'Drafting...' : 'Draft Briefing'}
                      </button>
                      {briefingData && (
                        <button
                          className="btn btn-outline btn-sm"
                          onClick={() => {
                            copyText(briefingData.content_markdown, () => {
                            setCopiedMemo(true);
                            setTimeout(() => setCopiedMemo(false), 2000);
                            });
                          }}
                        >
                          <Icon name="copy" size={13} />
                          {copiedMemo ? 'Copied Memo!' : 'Copy Memo'}
                        </button>
                      )}
                    </div>
                  </div>

                  {briefingData ? (
                    <div
                      style={{
                        background: 'var(--bg-inset)',
                        padding: '16px',
                        borderRadius: '8px',
                        border: '1px solid var(--border-subtle)',
                        maxHeight: '300px',
                        overflowY: 'auto',
                      }}
                    >
                      <pre
                        className="text-mono text-xs"
                        style={{ whiteSpace: 'pre-wrap', lineHeight: '1.6', color: 'var(--text-secondary)' }}
                      >
                        {briefingData.content_markdown}
                      </pre>
                    </div>
                  ) : (
                    <div className="text-secondary text-xs">
                      Click &quot;Draft Briefing&quot; to synthesize an executive incident report.
                    </div>
                  )}
                </div>

                {/* Section 3: Interactive Copilot Chat */}
                <div className="card">
                  <div className="flex items-center gap-2" style={{ marginBottom: 'var(--space-3)' }}>
                    <span className="text-accent"><Icon name="terminal" size={16} /></span>
                    <div>
                      <div className="font-bold text-md text-primary">Ask the AI guidance</div>
                      <div className="text-secondary text-xs">Ask specific questions regarding protocol compatibility, downgrade threats, or post-quantum risk.</div>
                    </div>
                  </div>

                  <div className="flex gap-2" style={{ marginBottom: 'var(--space-3)' }}>
                    <input
                      type="text"
                      className="input"
                      style={{ flex: 1 }}
                      placeholder="e.g. Will disabling TLS 1.0 cause downtime? What is the threat if left unpatched?"
                      aria-label="Ask about this session"
                      maxLength={4000}
                      value={copilotQuery}
                      onChange={(e) => setCopilotQuery(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') handleAskCopilot();
                      }}
                    />
                    <button
                      className="btn btn-primary"
                      onClick={() => handleAskCopilot()}
                      disabled={copilotLoading || !copilotQuery.trim()}
                    >
                      {copilotLoading ? 'Thinking...' : 'Ask Copilot'}
                    </button>
                  </div>

                  {/* Quick Prompts */}
                  <div className="flex gap-2 flex-wrap" style={{ marginBottom: 'var(--space-3)' }}>
                    <span className="text-xs text-muted" style={{ alignSelf: 'center' }}>Suggested:</span>
                    <button
                      className="btn btn-sm"
                      style={{
                        fontSize: '11px',
                        padding: '4px 10px',
                        borderRadius: '9999px',
                        background: 'rgba(16, 185, 129, 0.06)',
                        color: 'var(--accent)',
                        border: '1px solid rgba(16, 185, 129, 0.2)',
                        cursor: 'pointer',
                      }}
                      onClick={() => {
                        const q = 'Will disabling TLS 1.0 cause downtime or break legacy clients?';
                        setCopilotQuery(q);
                        handleAskCopilot(q);
                      }}
                    >
                      Zero-downtime migration?
                    </button>
                    <button
                      className="btn btn-sm"
                      style={{
                        fontSize: '11px',
                        padding: '4px 10px',
                        borderRadius: '9999px',
                        background: 'rgba(16, 185, 129, 0.06)',
                        color: 'var(--accent)',
                        border: '1px solid rgba(16, 185, 129, 0.2)',
                        cursor: 'pointer',
                      }}
                      onClick={() => {
                        const q = 'What is the exact threat vector if left unpatched?';
                        setCopilotQuery(q);
                        handleAskCopilot(q);
                      }}
                    >
                      Attack vector analysis?
                    </button>
                    <button
                      className="btn btn-sm"
                      style={{
                        fontSize: '11px',
                        padding: '4px 10px',
                        borderRadius: '9999px',
                        background: 'rgba(16, 185, 129, 0.06)',
                        color: 'var(--accent)',
                        border: '1px solid rgba(16, 185, 129, 0.2)',
                        cursor: 'pointer',
                      }}
                      onClick={() => {
                        const q = 'Is this session vulnerable to post-quantum harvest attacks?';
                        setCopilotQuery(q);
                        handleAskCopilot(q);
                      }}
                    >
                      Quantum harvest risk?
                    </button>
                  </div>

                  {copilotAnswer && (
                    <div
                      style={{
                        background: 'var(--bg-inset)',
                        padding: '16px',
                        borderRadius: '8px',
                        border: '1px solid var(--border-subtle)',
                      }}
                    >
                      <div className="flex justify-between items-center" style={{ marginBottom: 'var(--space-2)' }}>
                        <span className="font-bold text-xs text-accent">AI Copilot Response</span>
                        <span className="badge badge-info" style={{ fontSize: '10px' }}>{copilotEngine}</span>
                      </div>
                      <div
                        className="text-sm text-secondary"
                        style={{ whiteSpace: 'pre-wrap', lineHeight: '1.6' }}
                      >
                        {copilotAnswer}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
