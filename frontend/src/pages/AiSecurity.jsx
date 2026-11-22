import Notice from '../components/Notice';
import useClipboard from '../hooks/useClipboard';
import { useState, useEffect, useRef } from 'react';
import {
  getAiOverview,
  askGlobalCopilot,
  getSessions,
  getCopilotRemediation,
  getCopilotBriefing,
} from '../api/client';

const SUGGESTED_QUESTIONS = [
  { label: 'Downtime Risk', query: 'Will disabling TLS 1.0/1.1 cause downtime or break legacy email clients?' },
  { label: 'Post-Quantum', query: 'What is our exposure to Harvest Now, Decrypt Later quantum factoring attacks?' },
  { label: 'STARTTLS Strip', query: 'How does an active on-path adversary strip STARTTLS and how does MTA-STS stop it?' },
  { label: 'Cipher Hardening', query: 'Which cipher suites should we configure to satisfy NIST SP 800-52r2 and PCI-DSS v4.0?' },
  { label: 'Zero-Trust MTA', query: 'What are the required DNS TLSA and DANE records to mandate TLS encryption for mail relays?' },
];

const DAEMONS = [
  { id: 'postfix', name: 'Postfix', file: '/etc/postfix/main.cf' },
  { id: 'dovecot', name: 'Dovecot', file: '/etc/dovecot/conf.d/10-ssl.conf' },
  { id: 'exchange', name: 'Exchange', file: 'Set-ReceiveConnector.ps1' },
  { id: 'exim', name: 'Exim4', file: '/etc/exim4/exim4.conf' },
  { id: 'sendmail', name: 'Sendmail', file: '/etc/mail/sendmail.mc' },
];

export default function AiSecurity() {
  const { copyText, clipboardError } = useClipboard();
  const [toolView, setToolView] = useState('chat');
  const [aiData, setAiData] = useState(null);
  const [error, setError] = useState('');
  const [retryKey, setRetryKey] = useState(0);
  const retryAction = useRef(() => setRetryKey(key => key + 1));
  const [overviewLoading, setOverviewLoading] = useState(true);
  const remediationRequest = useRef(0);
  const briefingRequest = useRef(0);
  const [sessionsList, setSessionsList] = useState([]);
  const [selectedSessionId, setSelectedSessionId] = useState(null);

  // Copilot Chat
  const [chatLog, setChatLog] = useState([
    {
      sender: 'ai',
      text: 'Ask about a finding, a protocol, or a safer configuration.',
      engine: 'Security copilot',
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    },
  ]);
  const [queryInput, setQueryInput] = useState('');
  const [chatLoading, setChatLoading] = useState(false);
  const [copiedMsgIdx, setCopiedMsgIdx] = useState(null);

  // Remediation
  const [serverType, setServerType] = useState('postfix');
  const [remediationData, setRemediationData] = useState(null);
  const [remediationLoading, setRemediationLoading] = useState(false);
  const [copiedConfig, setCopiedConfig] = useState(false);
  const [copiedCommands, setCopiedCommands] = useState(false);

  // Briefing
  const [briefingData, setBriefingData] = useState(null);
  const [briefingLoading, setBriefingLoading] = useState(false);
  const [copiedBriefing, setCopiedBriefing] = useState(false);

  const chatContainerRef = useRef(null);

  useEffect(() => {
    let cancelled = false;
    setOverviewLoading(true); setError('');
    Promise.allSettled([getAiOverview(), getSessions(30)]).then(([overview, sessionResult]) => {
      if (cancelled) return;
      setAiData(overview.status === 'fulfilled' ? overview.value : null);
      if (sessionResult.status === 'fulfilled') {
        setSessionsList(sessionResult.value);
        setSelectedSessionId(previous => sessionResult.value.some(s => (s.id || s.session_id) === previous) ? previous : (sessionResult.value[0]?.id || sessionResult.value[0]?.session_id || null));
      }
      const failures = [overview, sessionResult].filter(result => result.status === 'rejected');
      if (failures.length) {
        retryAction.current = () => setRetryKey(key => key + 1);
        setError(`Some AI workspace data is unavailable. ${failures.map(result => result.reason?.message).join(' ')}`);
      }
      setOverviewLoading(false);
    });
    return () => { cancelled = true; };
  }, [retryKey]);

  useEffect(() => {
    if (chatContainerRef.current) {
      chatContainerRef.current.scrollTop = chatContainerRef.current.scrollHeight;
    }
  }, [chatLog]);

  const handleAskQuestion = async (qText) => {
    const q = qText || queryInput;
    if (!q || !q.trim() || chatLoading) return;

    setChatLog((prev) => [
      ...prev,
      {
        sender: 'user',
        text: q.trim(),
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      },
    ]);
    setQueryInput('');
    setChatLoading(true);

    try {
      const res = await askGlobalCopilot(q.trim(), selectedSessionId);
      setChatLog((prev) => [
        ...prev,
        {
          sender: 'ai',
          text: res.answer,
          engine: res.engine || 'Source unavailable',
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        },
      ]);
    } catch (err) {
      setChatLog((prev) => [
        ...prev,
        {
          sender: 'ai',
          text: `Failed to query AI copilot: ${err.message}`,
          engine: 'System Diagnostics',
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        },
      ]);
    } finally {
      setChatLoading(false);
    }
  };

  const handleGenerateRemediation = async (type = serverType, sessId = selectedSessionId) => {
    if (!sessId) return;
    const id = ++remediationRequest.current;
    setRemediationData(null); setError('');
    setRemediationLoading(true);
    try {
      const res = await getCopilotRemediation(sessId, type);
      if (id === remediationRequest.current) setRemediationData(res);
    } catch (err) {
      if (id === remediationRequest.current) {
        retryAction.current = () => handleGenerateRemediation(type, sessId);
        setError(`Could not generate configuration. ${err.message}`);
      }
    } finally {
      if (id === remediationRequest.current) setRemediationLoading(false);
    }
  };

  const handleGenerateBriefing = async (sessId = selectedSessionId) => {
    if (!sessId) return;
    const id = ++briefingRequest.current;
    setError('');
    setBriefingLoading(true);
    try {
      const res = await getCopilotBriefing(sessId);
      if (id === briefingRequest.current) setBriefingData(res);
    } catch (err) {
      if (id === briefingRequest.current) {
        retryAction.current = () => handleGenerateBriefing(sessId);
        setError(`Could not generate briefing. ${err.message}`);
      }
    } finally {
      if (id === briefingRequest.current) setBriefingLoading(false);
    }
  };

  // Clear generated content when its context changes. Generate only on request.
  useEffect(() => {
    setRemediationData(null); setBriefingData(null); setBriefingLoading(false);
    setError(''); retryAction.current = () => setRetryKey(key => key + 1);
    briefingRequest.current += 1;
    setRemediationLoading(false); setCopiedConfig(false); setCopiedCommands(false); setCopiedBriefing(false);
    return () => { remediationRequest.current += 1; briefingRequest.current += 1; };
  }, [selectedSessionId, serverType, retryKey]);

  const copyMessageText = (text, idx) => {
    copyText(text, () => {
      setCopiedMsgIdx(idx);
      setTimeout(() => setCopiedMsgIdx(null), 2000);
    });
  };

  return <div className="simple-page">
    <header className="simple-heading"><div><h1>AI security</h1><p>Understand findings and prepare your next steps.</p></div></header>
    {clipboardError && <Notice>{clipboardError}</Notice>}
    {error && <Notice onRetry={remediationLoading || briefingLoading || overviewLoading ? undefined : () => retryAction.current()}>{error}</Notice>}
    <div className="simple-row simple-context">
      <label className="simple-field" htmlFor="ai-session"><span>Session</span><select id="ai-session" className="select" value={selectedSessionId || ''} disabled={!sessionsList.length || chatLoading} onChange={event => setSelectedSessionId(Number(event.target.value))}>
        {!sessionsList.length && <option value="">{overviewLoading ? 'Loading…' : 'No sessions available'}</option>}
        {sessionsList.map(session => <option key={session.id || session.session_id} value={session.id || session.session_id}>#{session.id || session.session_id} · {session.src_ip} → {session.dst_ip}</option>)}
      </select></label>
      <div className="ui-segmented" role="group" aria-label="AI tools">{[['chat', 'Ask AI'], ['config', 'Configuration'], ['briefing', 'Briefing']].map(([id, label]) => <button key={id} type="button" aria-pressed={toolView === id} onClick={() => setToolView(id)}>{label}</button>)}</div>
    </div>
    {toolView === 'chat' && <section className="card simple-stack">
      <div className="simple-row"><h2>Ask about your security</h2><button className="text-action" disabled={chatLoading || chatLog.length < 2} onClick={() => setChatLog([chatLog[0]])}>Clear conversation</button></div>
      <div ref={chatContainerRef} className="simple-chat" role="log" aria-label="Conversation" aria-live="polite">
        {chatLog.map((message, index) => <article className={`simple-message ${message.sender}`} key={index}>
          <div className="simple-row"><strong>{message.sender === 'user' ? 'You' : 'Assistant'}</strong>{index > 0 && <button className="text-action" onClick={() => copyMessageText(message.text, index)} aria-label={`Copy message ${index + 1}`}>{copiedMsgIdx === index ? 'Copied' : 'Copy'}</button>}</div>
          {message.sender !== 'user' && <small className="text-secondary">{message.engine}</small>}<p>{message.text}</p>
        </article>)}
        {chatLoading && <p role="status" className="text-secondary text-sm">Preparing an answer…</p>}
      </div>
      <div className="ui-toolbar">{SUGGESTED_QUESTIONS.slice(0, 3).map(question => <button className="btn btn-outline" key={question.label} disabled={chatLoading} onClick={() => handleAskQuestion(question.query)}>{question.label}</button>)}</div>
      <form className="simple-chat-form" onSubmit={event => { event.preventDefault(); handleAskQuestion(); }}><label className="sr-only" htmlFor="ai-question">Your question</label><input id="ai-question" className="input" value={queryInput} onChange={event => setQueryInput(event.target.value)} placeholder="Ask a question…" disabled={chatLoading} /><button className="btn btn-primary" disabled={chatLoading || !queryInput.trim()}>Send</button></form>
    </section>}
    {toolView === 'config' && <section className="card simple-stack">
      <div className="simple-row"><h2>Suggested configuration</h2><div className="ui-toolbar"><label className="sr-only" htmlFor="ai-daemon">Mail server software</label><select id="ai-daemon" className="select" value={serverType} onChange={event => setServerType(event.target.value)}>{DAEMONS.map(daemon => <option key={daemon.id} value={daemon.id}>{daemon.name}</option>)}</select><button className="btn btn-primary" disabled={remediationLoading || !selectedSessionId} onClick={() => handleGenerateRemediation()}>{remediationLoading ? 'Generating…' : 'Generate'}</button></div></div>
      <p className="text-secondary text-sm">Rule-based configuration template. Review and test before applying; resolution is not verified.</p>
      {remediationLoading && <p role="status">Generating configuration…</p>}
      {remediationData ? <><div className="simple-row"><code>{remediationData.filepath}</code><button className="btn btn-outline" onClick={() => copyText(remediationData.config_content, () => { setCopiedConfig(true); setTimeout(() => setCopiedConfig(false), 2000); })}>{copiedConfig ? 'Copied' : 'Copy configuration'}</button></div><pre className="simple-code">{remediationData.config_content}</pre>
        {!!remediationData.commands?.length && <details className="simple-details"><summary>Deployment commands</summary><div className="simple-stack"><button className="text-action" onClick={() => copyText(remediationData.commands.join('\n'), () => { setCopiedCommands(true); setTimeout(() => setCopiedCommands(false), 2000); })}>{copiedCommands ? 'Copied' : 'Copy commands'}</button><pre className="simple-code">{remediationData.commands.join('\n')}</pre></div></details>}
      </> : !remediationLoading && <p className="simple-empty">Select a session and server, then generate a configuration.</p>}
    </section>}
    {toolView === 'briefing' && <section className="card simple-stack">
      <div className="simple-row"><h2>Session briefing</h2><div className="ui-toolbar"><button className="btn btn-primary" disabled={briefingLoading || !selectedSessionId} onClick={() => handleGenerateBriefing()}>{briefingLoading ? 'Drafting…' : 'Draft briefing'}</button>{briefingData && <button className="btn btn-outline" onClick={() => copyText(briefingData.content_markdown, () => { setCopiedBriefing(true); setTimeout(() => setCopiedBriefing(false), 2000); })}>{copiedBriefing ? 'Copied' : 'Copy'}</button>}</div></div>
      {briefingLoading && <p role="status">Preparing your briefing…</p>}
      {briefingData ? <article className="simple-prose"><small className="text-secondary">Rule-based briefing template</small><h3>{briefingData.title}</h3><p>{briefingData.content_markdown}</p></article> : !briefingLoading && <p className="simple-empty">Create a summary of the selected session’s risks and next steps.</p>}
    </section>}
    <details className="simple-details"><summary>Fleet insights</summary>
      {overviewLoading ? <p role="status">Loading insights…</p> : <div className="simple-insights">
        <div><h2>Anomaly detection</h2><dl className="simple-definition-list"><div><dt>Conformity rate</dt><dd>{aiData?.isolation_forest?.conformity_rate ?? '—'}</dd></div><div><dt>Anomalous sessions</dt><dd>{aiData?.isolation_forest?.anomalous_sessions ?? '—'}</dd></div></dl></div>
        <div><h2>Risk drivers</h2>{aiData?.explainable_ai?.primary_features?.length ? <dl className="simple-definition-list">{aiData.explainable_ai.primary_features.slice(0, 3).map(feature => <div key={feature.name}><dt>{feature.name.replace(/_/g, ' ')}</dt><dd>{Math.round(feature.weight * 100)}%</dd></div>)}</dl> : <p className="text-secondary text-sm">No attribution data.</p>}</div>
        <div><h2>Post-quantum readiness</h2><dl className="simple-definition-list"><div><dt>Score</dt><dd>{aiData?.post_quantum_readiness?.pqc_score ?? '—'} / 100</dd></div><div><dt>Status</dt><dd>{aiData?.post_quantum_readiness?.risk_status || 'Unknown'}</dd></div></dl></div>
      </div>}
    </details>
  </div>;
}
