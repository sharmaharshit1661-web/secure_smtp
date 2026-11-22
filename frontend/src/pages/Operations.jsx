import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import Notice from '../components/Notice';
import usePolling from '../hooks/usePolling';
import { getIdentity, getAgents, getAssessments, getOperations, getGraphWeaknesses, getRemediations, createAgent, revokeAgent, deleteAssessment, retryIntegrations, downloadReport } from '../api/client';

const time = value => value ? new Date(value).toLocaleString() : 'Not seen';
export default function Operations() {
  const [view, setView] = useState('agents');
  const [identity, setIdentity] = useState(null);
  const [data, setData] = useState({ agents: [], assessments: [], operations: {}, graph: {}, remediations: [] });
  const [error, setError] = useState('');
  const [actionError, setActionError] = useState('');
  const [busy, setBusy] = useState(false);
  const [name, setName] = useState('');
  const [credential, setCredential] = useState(null);
  const [updated, setUpdated] = useState(null);
  const generation = useRef(0);
  const admin = identity?.role === 'admin';
  async function load() {
    const id = ++generation.current;
    const keys = ['identity','agents','assessments','operations','graph','remediations'];
    const results = await Promise.allSettled([getIdentity(), getAgents(), getAssessments(), getOperations(), getGraphWeaknesses(), getRemediations()]);
    if (id !== generation.current) return;
    const messages = [];
    results.forEach((result, index) => {
      if (result.status === 'fulfilled') {
        if (index === 0) setIdentity(result.value);
        else setData(previous => ({...previous, [keys[index]]: result.value}));
      } else messages.push(`${keys[index]}: ${result.reason.message}`);
    });
    setError(messages.join(' · '));
    if (!messages.length) setUpdated(new Date());
  }
  useEffect(() => { load(); return () => { generation.current += 1; }; }, []);
  usePolling(load);
  async function act(action) {
    if (busy) return;
    setBusy(true); setActionError('');
    try { await action(); await load(); } catch (failure) { setActionError(failure.message); }
    finally { setBusy(false); }
  }
  return <main className="simple-page">
    <header className="simple-heading"><div><h1>Monitoring & operations</h1><p>Connect collectors, review assessments, and follow up on findings.</p></div><button className="btn btn-outline" onClick={load}>Refresh</button></header>
    <p className="text-secondary text-sm" role="status">{error ? 'Some data is stale or unavailable.' : updated ? `Updated ${updated.toLocaleTimeString()} · refreshes every 15 seconds` : 'Loading…'}</p>
    {error && <Notice onRetry={load}>{error}</Notice>}{actionError && <Notice>{actionError}</Notice>}
    <div className="ui-filter-group" role="group" aria-label="Operations view">{[['agents','Agents'],['assessments','Assessments'],['integrations','Integrations'],['remediations','Remediation']].map(([id,label]) => <button className="btn btn-outline" key={id} aria-pressed={view===id} onClick={() => setView(id)}>{label}</button>)}</div>
    {view==='agents' && <section className="simple-stack">
      <div className="simple-row"><h2>Connected agents</h2>{admin && <form className="ui-toolbar" onSubmit={event => { event.preventDefault(); act(async () => { setCredential(await createAgent(name.trim())); setName(''); }); }}><label className="sr-only" htmlFor="agent-name">Agent name</label><input id="agent-name" className="input" placeholder="Mail server or mirror name" value={name} maxLength={80} pattern="[A-Za-z0-9_ .-]+" onChange={event => setName(event.target.value)} required /><button className="btn btn-primary" disabled={busy || !name.trim()}>Create agent</button></form>}</div>
      {credential && <div className="card simple-stack" role="status"><h3>Save this credential now</h3><p className="text-secondary text-sm">It is shown once. Store it in a file readable only by the agent. Revoke and recreate the agent if it is lost.</p><code className="agent-credential">{credential.credential}</code><button className="btn btn-outline" onClick={() => setCredential(null)}>I have saved it</button></div>}
      {data.agents.length ? <div className="ui-table-scroll"><table className="ui-table"><thead><tr><th>Agent</th><th>Status</th><th>Last seen</th><th>Buffer / dropped</th><th>Capture</th>{admin && <th>Access</th>}</tr></thead><tbody>{data.agents.map(agent => <tr key={agent.agent_id}><td>{agent.name}</td><td>{agent.status}{agent.last_error && <small className="text-critical"> · Processing failed</small>}</td><td>{time(agent.last_seen)}</td><td>{agent.health?.queued_events ?? '—'} / {agent.health?.dropped_events ?? '—'}</td><td>{agent.health?.capture_active ? 'Collecting' : 'Stopped / not started'}{agent.health?.capture_errors > 0 && ` · ${agent.health.capture_errors} errors`}</td>{admin && <td><button className="text-action" disabled={busy || agent.revoked} onClick={() => { if (window.confirm(`Revoke ${agent.name}? Its collector will stop sending data.`)) act(() => revokeAgent(agent.agent_id)); }}>Revoke</button></td>}</tr>)}</tbody></table></div> : <p className="simple-empty">No agents registered. {admin ? 'Create an agent, then follow the installation steps.' : 'Ask your administrator to connect an authorized collector.'}</p>}
      <details className="simple-details"><summary>Installation and connection check</summary><div className="simple-stack"><p>Install on the mail server or an authorized mirrored interface that can see both directions. A browser or remote hosted dashboard cannot capture that network traffic.</p><pre className="simple-code">{`python -m pip install .\nchmod 600 /etc/secure-smtp/agent.credential\nsecure-smtp-agent --server https://YOUR-PILOT-DOMAIN \\\n  --interface YOUR-INTERFACE --authorized \\\n  --credential-file /etc/secure-smtp/agent.credential \\\n  --state /var/lib/secure-smtp-agent/outbox.sqlite`}</pre><p className="text-secondary text-sm">The interface needs packet-capture permissions. Heartbeats appear within 15 seconds. Check HTTPS trust, interface selection and service logs if offline. Payloads stay in bounded memory; only cryptographic metadata is sent. Offline buffers are bounded and dropped observations are counted.</p></div></details>
    </section>}
    {view==='assessments' && <section className="simple-stack"><h2>Assessment history</h2><p className="text-secondary text-sm">Retained for {identity?.retention_days ?? '—'} days. Sources distinguish passive agent observations, manual captures, and controlled scenarios.</p>{data.assessments.length ? data.assessments.map(job => <article key={job.job_id} className="simple-details"><div className="simple-row"><div><strong>{job.source_kind?.replaceAll('_',' ') || 'Unknown source'}</strong><p className="text-secondary text-sm">{job.pcap_filename || job.job_id} · {time(job.created_at)}</p><p>{job.status}{job.error_message && ` — ${job.error_message}`}</p></div><div className="ui-toolbar">{job.status==='done' && ['pdf','html','json'].map(format => <button className="btn btn-outline" key={format} disabled={busy} onClick={() => act(() => downloadReport(job.job_id,format))}>{format.toUpperCase()}</button>)}{admin && !['queued','running'].includes(job.status) && <button className="text-action" disabled={busy} onClick={() => { if (window.confirm('Delete this assessment, its sessions and reports? This cannot be undone.')) act(() => deleteAssessment(job.job_id)); }}>Delete</button>}</div></div>{job.integrations && <p className="text-secondary text-sm">Graph: {job.integrations.graph?.status || 'Unknown'} · Alerts: {job.integrations.alerts?.status || 'Unknown'} {admin && <button className="text-action" disabled={busy} onClick={() => act(() => retryIntegrations(job.job_id))}>Retry integrations</button>}</p>}</article>) : <p className="simple-empty">Assessments appear after a capture upload or agent ingestion.</p>}</section>}
    {view==='integrations' && <section className="simple-stack"><h2>Hosts sharing a weakness</h2><p className="text-secondary text-sm">Neo4j: {error.includes('graph:') ? 'Unavailable' : data.graph.status || 'Loading'}</p>{data.graph.groups?.map(group => <div className="simple-details" key={group.rule}><strong>{group.rule}</strong><p>{group.hosts.join(', ')}</p><div className="ui-toolbar">{group.sessions.map(id => <Link className="text-action" key={id} to={`/dashboard/sessions?session=${id}`}>Session #{id}</Link>)}</div></div>)}<details className="simple-details"><summary>Alert delivery history</summary><div className="ui-table-scroll"><table className="ui-table"><thead><tr><th>Session</th><th>Delivery</th><th>Attempts</th></tr></thead><tbody>{data.operations.alerts?.map(alert => <tr key={`${alert.session_id}:${alert.updated_at}`}><td><Link to={`/dashboard/sessions?session=${alert.session_id}`}>#{alert.session_id}</Link></td><td>{alert.status}</td><td>{alert.attempts}</td></tr>)}</tbody></table></div></details><p>Retention: {data.operations.retention?.status || 'Not checked yet'}</p>{admin && <details className="simple-details"><summary>Administrative audit history</summary>{data.operations.audit?.map((entry,index) => <p key={index} className="text-secondary text-sm">{time(entry.created_at)} · {entry.action} · {entry.outcome}</p>)}</details>}</section>}
    {view==='remediations' && <section className="simple-stack"><h2>Follow-up evidence</h2><p className="text-secondary text-sm">Track a finding from Session Explorer. Later observations are supporting evidence; an issue disappearing from a sample does not prove it is resolved.</p>{data.remediations.map(item => <article className="simple-details" key={`${item.session_id}:${item.rule_id}`}><strong>{item.rule_id}</strong><p>{item.status.replaceAll('_',' ')}</p><div className="ui-toolbar"><Link className="text-action" to={`/dashboard/sessions?session=${item.session_id}`}>Original finding</Link>{item.evidence.map(e => <Link className="text-action" key={e.session_id} to={`/dashboard/sessions?session=${e.session_id}`}>#{e.session_id}: {e.still_observed ? 'still observed' : 'not observed'}</Link>)}</div></article>)}</section>}
  </main>;
}
