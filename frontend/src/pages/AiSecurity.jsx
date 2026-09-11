import { useState, useEffect, useRef } from 'react';
import Icon from '../components/Icon';
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
  const [aiData, setAiData] = useState(null);
  const [sessionsList, setSessionsList] = useState([]);
  const [selectedSessionId, setSelectedSessionId] = useState(null);

  // Copilot Chat
  const [chatLog, setChatLog] = useState([
    {
      sender: 'ai',
      text: 'Neural Defense Engine online. Query me on cryptographic posture, zero-downtime hardening, MITM mitigation, or post-quantum readiness across your monitored mail relays.',
      engine: 'Expert Cryptographic Synthesizer',
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
    getAiOverview()
      .then((data) => setAiData(data))
      .catch((err) => console.error('Failed to load AI overview:', err));

    getSessions(30)
      .then((sessList) => {
        if (sessList && sessList.length > 0) {
          setSessionsList(sessList);
          setSelectedSessionId(sessList[0].id || sessList[0].session_id);
        }
      })
      .catch((err) => console.error('Failed to load sessions for AI security:', err));
  }, []);

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
          engine: res.engine || 'Built-in Synthesizer',
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
    setRemediationLoading(true);
    try {
      const res = await getCopilotRemediation(sessId, type);
      setRemediationData(res);
    } catch (err) {
      console.error('Failed to synthesize remediation:', err);
    } finally {
      setRemediationLoading(false);
    }
  };

  const handleGenerateBriefing = async (sessId = selectedSessionId) => {
    if (!sessId) return;
    setBriefingLoading(true);
    try {
      const res = await getCopilotBriefing(sessId);
      setBriefingData(res);
    } catch (err) {
      console.error('Failed to generate briefing:', err);
    } finally {
      setBriefingLoading(false);
    }
  };

  // Auto-generate remediation when target session or daemon changes
  useEffect(() => {
    if (selectedSessionId) {
      handleGenerateRemediation(serverType, selectedSessionId);
    }
  }, [selectedSessionId, serverType]);

  const copyMessageText = (text, idx) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedMsgIdx(idx);
      setTimeout(() => setCopiedMsgIdx(null), 2000);
    });
  };

  const activeSessionObj = sessionsList.find(
    (s) => (s.id || s.session_id) === Number(selectedSessionId)
  );

  return (
    <div className="flex flex-col gap-6" style={{ maxWidth: '1440px', margin: '0 auto', paddingBottom: 'var(--space-8)' }}>
      {/* Header */}
      <div className="page-header animate-in">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4" style={{ width: '100%' }}>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="page-title" style={{ margin: 0 }}>
                <span className="page-title-icon"><Icon name="brain" size={22} /></span>
                AI Security Center
              </h1>
              <span className="badge badge-accent text-mono" style={{ fontSize: '11px' }}>
                NEURAL COPILOT ONLINE
              </span>
            </div>
            <p className="page-subtitle">
              Autonomous cryptographic copilot, SHAP risk attribution, and daemon remediation directives.
            </p>
          </div>

          <div className="flex items-center gap-3 flex-wrap">
            <div
              style={{
                background: 'var(--bg-surface)',
                border: '1px solid var(--border-strong)',
                borderRadius: 'var(--radius-sm)',
                padding: '6px 14px',
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                fontFamily: 'var(--font-mono)',
                fontSize: '11px',
              }}
            >
              <span className="status-dot status-dot-active" />
              <span style={{ color: 'var(--text-muted)' }}>ENGINE:</span>
              <span style={{ color: 'var(--accent)', fontWeight: 700 }}>
                {aiData?.engine ? 'EXPERT_SYNTHESIZER' : 'ACTIVE'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Top Row: 3 AI Intelligence Telemetry Cards */}
      <div className="grid grid-1 md:grid-3 gap-4">
        {/* Card 1: Isolation Forest Anomaly Radar */}
        <div className="card animate-in" style={{ padding: '18px 20px' }}>
          <div className="flex justify-between items-center" style={{ marginBottom: '10px' }}>
            <div className="flex items-center gap-2">
              <span style={{ color: 'var(--accent)' }}><Icon name="activity" size={15} /></span>
              <span className="font-bold text-sm" style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
                Isolation Forest Radar
              </span>
            </div>
            <span className="badge badge-clean text-mono" style={{ fontSize: '10px' }}>
              ONLINE
            </span>
          </div>

          <div className="flex items-baseline gap-2" style={{ marginBottom: '8px' }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              {aiData?.isolation_forest?.conformity_rate || '100.0%'}
            </div>
            <div className="text-muted text-xs font-mono">Conformity Rate</div>
          </div>

          <div className="flex flex-wrap gap-1" style={{ marginBottom: '12px' }}>
            {['Packet Volume', 'Cipher Suite', 'Timing Signature'].map((vec, idx) => (
              <span
                key={idx}
                className="badge text-mono"
                style={{ fontSize: '9px', background: 'var(--bg-inset)', color: 'var(--text-secondary)' }}
              >
                {vec}
              </span>
            ))}
          </div>

          <div className="flex justify-between items-center pt-2 text-xs font-mono text-muted" style={{ borderTop: '1px solid var(--border)' }}>
            <span>Anomalous Events:</span>
            <span
              style={{
                color: (aiData?.isolation_forest?.anomalous_sessions ?? 0) > 0 ? 'var(--sev-critical)' : 'var(--sev-clean)',
                fontWeight: 700,
              }}
            >
              {aiData?.isolation_forest?.anomalous_sessions ?? 0} Detected
            </span>
          </div>
        </div>

        {/* Card 2: Feature Attribution (SHAP) */}
        <div className="card animate-in" style={{ padding: '18px 20px' }}>
          <div className="flex justify-between items-center" style={{ marginBottom: '10px' }}>
            <div className="flex items-center gap-2">
              <span style={{ color: 'var(--accent)' }}><Icon name="chart" size={15} /></span>
              <span className="font-bold text-sm" style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
                SHAP Risk Attribution
              </span>
            </div>
            <span className="badge badge-accent text-mono" style={{ fontSize: '10px' }}>
              XGBOOST
            </span>
          </div>

          <div className="flex flex-col gap-2" style={{ marginBottom: '10px' }}>
            {(aiData?.explainable_ai?.primary_features || [
              { name: 'tls_downgrade_detected', weight: 0.38 },
              { name: 'cipher_suite_aead', weight: 0.26 },
              { name: 'cert_expiration_window', weight: 0.21 },
            ]).slice(0, 3).map((feat) => (
              <div key={feat.name} className="flex justify-between items-center text-xs font-mono">
                <span className="text-secondary truncate" style={{ maxWidth: '160px', fontSize: '11px' }}>
                  {feat.name.replace(/_/g, ' ')}
                </span>
                <div className="flex items-center gap-2">
                  <div style={{ width: '54px', height: '4px', background: 'var(--bg-inset)', borderRadius: '2px', overflow: 'hidden' }}>
                    <div style={{ width: `${feat.weight * 100}%`, height: '100%', background: 'var(--accent)' }} />
                  </div>
                  <span style={{ color: 'var(--text-primary)', fontWeight: 650, fontSize: '11px', width: '28px', textAlign: 'right' }}>
                    {Math.round(feat.weight * 100)}%
                  </span>
                </div>
              </div>
            ))}
          </div>

          <div className="flex justify-between items-center pt-2 text-xs font-mono text-muted" style={{ borderTop: '1px solid var(--border)' }}>
            <span>Attribution Model:</span>
            <span style={{ color: 'var(--accent)', fontWeight: 600 }}>Shapley Additive</span>
          </div>
        </div>

        {/* Card 3: Post-Quantum Exposure (PQC) */}
        <div className="card animate-in" style={{ padding: '18px 20px' }}>
          <div className="flex justify-between items-center" style={{ marginBottom: '10px' }}>
            <div className="flex items-center gap-2">
              <span style={{ color: 'var(--accent)' }}><Icon name="shield" size={15} /></span>
              <span className="font-bold text-sm" style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
                Post-Quantum Radar
              </span>
            </div>
            <span
              className={`badge ${(aiData?.post_quantum_readiness?.vulnerable_sessions ?? 0) > 0 ? 'badge-critical' : 'badge-clean'} text-mono`}
              style={{ fontSize: '10px' }}
            >
              {aiData?.post_quantum_readiness?.risk_status || 'MONITORED'}
            </span>
          </div>

          <div className="flex items-baseline gap-2" style={{ marginBottom: '8px' }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '1.75rem', fontWeight: 700, color: 'var(--accent)' }}>
              {aiData?.post_quantum_readiness?.pqc_score ?? 57}
              <span style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>/100</span>
            </div>
            <div className="text-muted text-xs font-mono">PQC Readiness Index</div>
          </div>

          <div className="text-secondary text-xs" style={{ fontSize: '11px', lineHeight: '1.4', marginBottom: '10px' }}>
            Harvest Now, Decrypt Later (HNDL) exposure across non-ephemeral sessions.
          </div>

          <div className="flex justify-between items-center pt-2 text-xs font-mono text-muted" style={{ borderTop: '1px solid var(--border)' }}>
            <span>Target Primitive:</span>
            <span style={{ color: 'var(--accent)', fontWeight: 600 }}>ML-KEM-768</span>
          </div>
        </div>
      </div>

      {/* Target Session Context Strip */}
      <div
        className="card"
        style={{
          padding: '12px 18px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '12px',
        }}
      >
        <div className="flex items-center gap-2">
          <span style={{ color: 'var(--accent)' }}><Icon name="target" size={16} /></span>
          <span className="font-bold text-xs text-primary" style={{ fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>
            Session Telemetry Target:
          </span>
        </div>

        <div className="flex items-center gap-3 flex-wrap" style={{ flex: 1, maxWidth: '640px' }}>
          <select
            className="select font-mono text-xs"
            style={{ width: '100%', padding: '5px 10px' }}
            value={selectedSessionId || ''}
            onChange={(e) => setSelectedSessionId(Number(e.target.value))}
          >
            {sessionsList.map((s) => {
              const sId = s.id || s.session_id;
              const rScore = Math.round(s.risk_score || 0);
              return (
                <option key={sId} value={sId}>
                  Session #{sId} · {s.src_ip} → {s.dst_ip}:{s.dst_port} · Risk: {rScore}/100 [{s.tls_mode?.toUpperCase() || 'PLAINTEXT'}]
                </option>
              );
            })}
          </select>
        </div>

        {activeSessionObj && (
          <span
            className={`badge ${activeSessionObj.risk_score > 50 ? 'badge-critical' : activeSessionObj.risk_score > 0 ? 'badge-high' : 'badge-clean'} text-mono`}
            style={{ fontSize: '10px' }}
          >
            RISK: {Math.round(activeSessionObj.risk_score || 0)}
          </span>
        )}
      </div>

      {/* Main Grid: Copilot Console & Autonomous Directives */}
      <div className="grid grid-1 lg:grid-2 gap-6" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(480px, 1fr))' }}>
        
        {/* LEFT COLUMN: Security Copilot Console */}
        <div className="copilot-chat-window">
          {/* Header */}
          <div className="copilot-chat-header">
            <div className="flex items-center gap-2">
              <span style={{ color: 'var(--accent)', fontFamily: 'var(--font-mono)', fontSize: '13px', fontWeight: 700 }}>
                &gt;_
              </span>
              <span className="text-mono text-xs font-semibold" style={{ color: 'var(--text-primary)', letterSpacing: '0.04em' }}>
                COPILOT CONSOLE · Session #{selectedSessionId || 'Fleet'}
              </span>
            </div>

            <div className="flex items-center gap-2">
              <button
                className="btn btn-outline btn-sm"
                style={{ fontSize: '11px', padding: '3px 10px', gap: '4px' }}
                onClick={() => setChatLog([chatLog[0]])}
              >
                <Icon name="trash" size={11} /> Clear Log
              </button>
            </div>
          </div>

          {/* Chat Stream */}
          <div ref={chatContainerRef} className="copilot-chat-screen">
            {chatLog.map((msg, idx) => (
              <div
                key={idx}
                className={msg.sender === 'user' ? 'copilot-msg-user' : 'copilot-msg-ai'}
              >
                <div className="flex justify-between items-center gap-4 text-xs text-muted" style={{ marginBottom: '6px', fontSize: '11px' }}>
                  <span style={{ color: msg.sender === 'user' ? 'var(--accent)' : 'var(--text-primary)', fontWeight: 650 }}>
                    {msg.sender === 'user' ? 'Security Analyst' : 'AI Defense Copilot'}
                  </span>
                  <div className="flex items-center gap-2">
                    <span className="font-mono" style={{ fontSize: '10px' }}>{msg.timestamp}</span>
                    {msg.sender === 'ai' && (
                      <button
                        type="button"
                        className="btn btn-outline btn-xs"
                        style={{ padding: '1px 6px', fontSize: '9px', height: '18px' }}
                        onClick={() => copyMessageText(msg.text, idx)}
                      >
                        <Icon name={copiedMsgIdx === idx ? 'check' : 'copy'} size={9} />
                        {copiedMsgIdx === idx ? 'Copied' : 'Copy'}
                      </button>
                    )}
                  </div>
                </div>

                <div
                  style={{
                    whiteSpace: 'pre-wrap',
                    color: msg.sender === 'user' ? 'var(--text-primary)' : 'var(--text-secondary)',
                    fontSize: '12px',
                    lineHeight: '1.6',
                    fontFamily: msg.sender === 'user' ? 'var(--font-mono)' : 'inherit',
                  }}
                >
                  {msg.text}
                </div>

                {msg.engine && (
                  <div className="text-muted text-right font-mono" style={{ marginTop: '6px', fontSize: '10px' }}>
                    Engine: {msg.engine}
                  </div>
                )}
              </div>
            ))}

            {chatLoading && (
              <div style={{ color: 'var(--accent)', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '8px', padding: '6px 10px' }}>
                <span className="status-dot status-dot-active" />
                <span className="font-mono text-xs">Synthesizing cryptographic assessment...</span>
              </div>
            )}
          </div>

          {/* Prompt Chips */}
          <div
            style={{
              padding: '8px 14px',
              background: '#09090C',
              borderTop: '1px solid var(--border)',
              display: 'flex',
              gap: '6px',
              flexWrap: 'wrap',
              alignItems: 'center',
            }}
          >
            <span className="text-xs text-muted font-mono" style={{ fontSize: '10px', marginRight: '4px' }}>PROMPTS:</span>
            {SUGGESTED_QUESTIONS.map((sq) => (
              <button
                key={sq.label}
                type="button"
                className="copilot-prompt-pill"
                onClick={() => handleAskQuestion(sq.query)}
              >
                {sq.label}
              </button>
            ))}
          </div>

          {/* Chat Input Bar */}
          <div
            style={{
              padding: '12px 14px',
              background: '#070709',
              borderTop: '1px solid var(--border)',
              display: 'flex',
              gap: '10px',
            }}
          >
            <input
              type="text"
              className="input text-xs"
              placeholder="Ask Copilot e.g. How to mitigate STARTTLS downgrade on Postfix?"
              value={queryInput}
              onChange={(e) => setQueryInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') handleAskQuestion();
              }}
              style={{ flex: 1, padding: '6px 12px' }}
            />
            <button
              type="button"
              className="btn btn-primary btn-sm"
              onClick={() => handleAskQuestion()}
              disabled={chatLoading || !queryInput.trim()}
              style={{ padding: '6px 14px', gap: '6px' }}
            >
              <Icon name="send" size={12} />
              <span>Ask Copilot</span>
            </button>
          </div>
        </div>

        {/* RIGHT COLUMN: Autonomous Directives & CISO Briefing */}
        <div className="flex flex-col gap-5">
          
          {/* Card 1: Autonomous Server Remediation */}
          <div className="card" style={{ padding: '20px' }}>
            <div className="flex justify-between items-center flex-wrap gap-2" style={{ marginBottom: '14px' }}>
              <div className="flex items-center gap-2">
                <span style={{ color: 'var(--accent)' }}><Icon name="file" size={15} /></span>
                <span className="font-bold text-sm" style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  Autonomous Remediation Stanzas
                </span>
              </div>

              {remediationData && (
                <button
                  type="button"
                  className="btn btn-outline btn-sm"
                  style={{ fontSize: '11px', padding: '3px 10px', gap: '4px' }}
                  onClick={() => {
                    navigator.clipboard.writeText(remediationData.config_content);
                    setCopiedConfig(true);
                    setTimeout(() => setCopiedConfig(false), 2000);
                  }}
                >
                  <Icon name={copiedConfig ? 'check' : 'copy'} size={11} />
                  {copiedConfig ? 'Copied' : 'Copy Stanza'}
                </button>
              )}
            </div>

            {/* Daemon Tabs */}
            <div className="flex gap-1 flex-wrap" style={{ marginBottom: '12px' }}>
              {DAEMONS.map((d) => (
                <button
                  key={d.id}
                  type="button"
                  className={`daemon-tab-btn ${serverType === d.id ? 'active' : ''}`}
                  onClick={() => setServerType(d.id)}
                >
                  {d.name}
                </button>
              ))}
            </div>

            {remediationData ? (
              <div className="flex flex-col gap-3">
                <div className="flex justify-between items-center text-xs font-mono" style={{ fontSize: '11px' }}>
                  <span className="text-muted">Target Config:</span>
                  <span style={{ color: 'var(--accent)', fontWeight: 600 }}>{remediationData.filepath}</span>
                </div>

                <pre
                  style={{
                    background: '#040406',
                    border: '1px solid var(--border-strong)',
                    borderRadius: 'var(--radius-sm)',
                    padding: '12px 14px',
                    color: '#34D399',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '11px',
                    lineHeight: '1.6',
                    maxHeight: '220px',
                    overflowX: 'auto',
                    margin: 0,
                  }}
                >
                  {remediationData.config_content}
                </pre>

                {remediationData.commands && remediationData.commands.length > 0 && (
                  <div>
                    <div className="flex justify-between items-center text-xs font-mono" style={{ marginBottom: '4px', fontSize: '11px' }}>
                      <span className="text-muted">Deployment Commands:</span>
                      <button
                        type="button"
                        className="btn btn-outline btn-xs"
                        style={{ fontSize: '10px', padding: '1px 6px' }}
                        onClick={() => {
                          navigator.clipboard.writeText(remediationData.commands.join('\n'));
                          setCopiedCommands(true);
                          setTimeout(() => setCopiedCommands(false), 2000);
                        }}
                      >
                        <Icon name={copiedCommands ? 'check' : 'copy'} size={10} />
                        {copiedCommands ? 'Copied' : 'Copy Commands'}
                      </button>
                    </div>
                    <pre
                      style={{
                        background: '#070709',
                        border: '1px solid var(--border)',
                        borderRadius: 'var(--radius-sm)',
                        padding: '8px 12px',
                        color: 'var(--text-secondary)',
                        fontFamily: 'var(--font-mono)',
                        fontSize: '11px',
                        lineHeight: '1.5',
                        margin: 0,
                        overflowX: 'auto',
                      }}
                    >
                      {remediationData.commands.join('\n')}
                    </pre>
                  </div>
                )}
              </div>
            ) : (
              <div style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '30px 20px', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                {remediationLoading ? 'Synthesizing configuration stanza...' : 'Select a daemon to generate automated hardening directives.'}
              </div>
            )}
          </div>

          {/* Card 2: Executive CISO Incident Briefing */}
          <div className="card" style={{ padding: '20px' }}>
            <div className="flex justify-between items-center flex-wrap gap-2" style={{ marginBottom: '14px' }}>
              <div className="flex items-center gap-2">
                <span style={{ color: 'var(--accent)' }}><Icon name="clipboard" size={15} /></span>
                <span className="font-bold text-sm" style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  Executive CISO Incident Memo
                </span>
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  className="btn btn-primary btn-sm"
                  style={{ fontSize: '11px', padding: '3px 10px' }}
                  onClick={() => handleGenerateBriefing()}
                  disabled={briefingLoading || !selectedSessionId}
                >
                  {briefingLoading ? 'Drafting…' : 'Draft Memo'}
                </button>

                {briefingData && (
                  <button
                    type="button"
                    className="btn btn-outline btn-sm"
                    style={{ fontSize: '11px', padding: '3px 10px', gap: '4px' }}
                    onClick={() => {
                      navigator.clipboard.writeText(briefingData.content_markdown);
                      setCopiedBriefing(true);
                      setTimeout(() => setCopiedBriefing(false), 2000);
                    }}
                  >
                    <Icon name={copiedBriefing ? 'check' : 'copy'} size={11} />
                    {copiedBriefing ? 'Copied' : 'Copy Memo'}
                  </button>
                )}
              </div>
            </div>

            {briefingData ? (
              <div
                style={{
                  background: 'var(--bg-inset)',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '14px 16px',
                  maxHeight: '220px',
                  overflowY: 'auto',
                  fontSize: '12px',
                  lineHeight: '1.6',
                  color: 'var(--text-secondary)',
                }}
              >
                <div style={{ color: 'var(--text-primary)', fontWeight: 700, marginBottom: '6px', fontSize: '13px' }}>
                  {briefingData.title}
                </div>
                <div style={{ whiteSpace: 'pre-wrap', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                  {briefingData.content_markdown}
                </div>
              </div>
            ) : (
              <div style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '30px 20px', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                Click &quot;Draft Memo&quot; to synthesize a boardroom-ready regulatory and technical briefing for the selected session.
              </div>
            )}
          </div>

        </div>
      </div>
    </div>
  );
}
