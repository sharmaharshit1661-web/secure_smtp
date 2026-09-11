import { useState, useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import Icon from '../components/Icon';
import { dispatchCustomMail, getLiveStatus } from '../api/client';

const SCENARIOS = [
  {
    id: 'stripping',
    port: 2528,
    name: 'STARTTLS Stripping Attack',
    badge: 'CRITICAL',
    badgeClass: 'badge-critical',
    color: 'var(--severity-critical)',
    glow: 'rgba(239, 68, 68, 0.25)',
    icon: 'alert',
    shortDesc: 'Active MitM proxy forces unencrypted cleartext by intercepting EHLO.',
    defaultSubject: 'URGENT: Executive Wire Transfer Authorization',
    defaultBody: 'Wire $450,000 to routing #984128912 immediately. Token: SEC_AUTH_9921_PLAINTEXT',
  },
  {
    id: 'plaintext',
    port: 2525,
    name: 'Plaintext Transmission',
    badge: 'HIGH RISK',
    badgeClass: 'badge-high',
    color: 'var(--severity-high)',
    glow: 'rgba(249, 115, 22, 0.25)',
    icon: 'lock',
    shortDesc: 'Unencrypted transmission on standard SMTP port with zero TLS layer.',
    defaultSubject: 'Internal Database Backup Credentials',
    defaultBody: 'DB_HOST=prod-db.internal DB_USER=root DB_PASS=SuperSecret2026! PII records: 14,200',
  },
  {
    id: 'vulnerable',
    port: 2527,
    name: 'Legacy TLS / Expired Cert',
    badge: 'WEAK CRYPTO',
    badgeClass: 'badge-medium',
    color: 'var(--severity-medium)',
    glow: 'rgba(250, 204, 21, 0.25)',
    icon: 'certificate',
    shortDesc: 'Negotiates deprecated TLS with expired X.509 certificate.',
    defaultSubject: 'Quarterly Compliance Audit',
    defaultBody: 'Quarterly compliance telemetry report for legacy mail relays in cluster west-2.',
  },
  {
    id: 'tls_modern',
    port: 2526,
    name: 'Hardened TLS 1.3 Baseline',
    badge: 'SECURE',
    badgeClass: 'badge-clean',
    color: 'var(--severity-healthy)',
    glow: 'rgba(16, 185, 129, 0.25)',
    icon: 'check',
    shortDesc: 'Gold-standard TLS 1.3 with Perfect Forward Secrecy & AEAD ciphers.',
    defaultSubject: 'Secured Cryptographic Transmission',
    defaultBody: 'Verified end-to-end TLS 1.3 encryption handshake with authenticated cipher suite.',
  },
];

const PRESETS = [
  { label: 'Wire Transfer', subject: 'URGENT: Executive Wire Transfer Authorization', body: 'Wire $450,000 to routing #984128912 immediately. Token: SEC_AUTH_9921_PLAINTEXT' },
  { label: 'DB Credentials', subject: 'Database Credentials Backup', body: 'DB_HOST=prod-db.internal DB_USER=postgres DB_PASS=SuperSecretKey2026! PII records: 14,200' },
  { label: 'Executive Brief', subject: 'Confidential M&A Acquisition Details', body: 'Project Titan acquisition terms finalized. Target valuation: $12.4M. Review attached brief.' },
  { label: 'Health Ping', subject: 'Routine Mail Relay Health Check', body: 'System telemetry heartbeat OK. No anomalous network behavior detected.' },
];

export default function ClientDispatcher() {
  const [selectedScenario, setSelectedScenario] = useState('stripping');
  const [clientName, setClientName] = useState("Friend's Laptop");
  const [sender, setSender] = useState('alice@friend-device.local');
  const [recipient, setRecipient] = useState('bob@securesmtp.local');
  const [subject, setSubject] = useState(SCENARIOS[0].defaultSubject);
  const [body, setBody] = useState(SCENARIOS[0].defaultBody);
  const [serverHost, setServerHost] = useState(window.location.hostname || '127.0.0.1');

  const [loading, setLoading] = useState(false);
  const [transcript, setTranscript] = useState([]);
  const [lastResult, setLastResult] = useState(null);
  const [error, setError] = useState(null);
  const [liveStatus, setLiveStatus] = useState(null);
  const [continuousMode, setContinuousMode] = useState(false);
  const [showCliModal, setShowCliModal] = useState(false);
  const [copiedTranscript, setCopiedTranscript] = useState(false);

  const terminalContainerRef = useRef(null);
  const continuousTimerRef = useRef(null);

  useEffect(() => {
    getLiveStatus()
      .then((data) => {
        setLiveStatus(data);
        if (data?.lan_ip && (!serverHost || serverHost === 'localhost' || serverHost === '127.0.0.1')) {
          setServerHost(data.lan_ip);
        }
      })
      .catch(() => {});
  }, [serverHost]);

  useEffect(() => {
    if (terminalContainerRef.current) {
      terminalContainerRef.current.scrollTop = terminalContainerRef.current.scrollHeight;
    }
  }, [transcript]);

  const handleScenarioSelect = (scId) => {
    setSelectedScenario(scId);
    const sc = SCENARIOS.find((s) => s.id === scId);
    if (sc) {
      setSubject(sc.defaultSubject);
      setBody(sc.defaultBody);
    }
  };

  const handleTransmit = async (scenarioOverride) => {
    const scId = scenarioOverride || selectedScenario;
    const currentSc = SCENARIOS.find((s) => s.id === scId) || SCENARIOS[0];

    setLoading(true);
    setError(null);

    setTranscript((prev) => [
      ...prev,
      {
        timestamp: new Date().toLocaleTimeString(),
        direction: 'info',
        text: `>> INITIATING_TRANSMISSION: ${currentSc.name.toUpperCase()} (PORT ${currentSc.port})`,
      },
    ]);

    try {
      const payload = {
        server_ip: serverHost || '127.0.0.1',
        port: currentSc.port,
        scenario: currentSc.id,
        sender,
        recipient,
        subject,
        body,
        client_name: clientName || "Friend's Laptop",
      };

      const res = await dispatchCustomMail(payload);
      if (res.transcript) {
        setTranscript((prev) => [...prev, ...res.transcript]);
      }
      setLastResult(res);
    } catch (err) {
      setError(err.message || 'Transmission failed. Ensure server listener is active.');
      setTranscript((prev) => [
        ...prev,
        {
          timestamp: new Date().toLocaleTimeString(),
          direction: 'error',
          text: `[CONNECTION_ERROR] ${err.message}`,
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (continuousMode) {
      let step = 0;
      const order = ['stripping', 'plaintext', 'vulnerable', 'tls_modern'];
      continuousTimerRef.current = setInterval(() => {
        const nextSc = order[step % order.length];
        setSelectedScenario(nextSc);
        handleTransmit(nextSc);
        step += 1;
      }, 7000);
    } else {
      if (continuousTimerRef.current) {
        clearInterval(continuousTimerRef.current);
      }
    }
    return () => {
      if (continuousTimerRef.current) clearInterval(continuousTimerRef.current);
    };
  }, [continuousMode, serverHost, clientName, sender, recipient, subject, body]);

  const copyTranscriptToClipboard = () => {
    if (!transcript.length) return;
    const text = transcript.map(t => `${t.timestamp} [${t.direction.toUpperCase()}] ${t.text}`).join('\n');
    navigator.clipboard.writeText(text).then(() => {
      setCopiedTranscript(true);
      setTimeout(() => setCopiedTranscript(false), 2000);
    });
  };

  const activeScObj = SCENARIOS.find((s) => s.id === selectedScenario) || SCENARIOS[0];

  return (
    <div className="flex flex-col gap-6" style={{ maxWidth: '1440px', margin: '0 auto', paddingBottom: 'var(--space-8)' }}>
      {/* Top Header */}
      <div className="page-header animate-in">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4" style={{ width: '100%' }}>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="page-title" style={{ margin: 0 }}>
                <span className="page-title-icon"><Icon name="send" size={22} /></span>
                Client Dispatcher
              </h1>
            </div>
            <p className="page-subtitle">
              Direct socket transmission engine for cryptographic attack simulation and protocol validation.
            </p>
          </div>

          {/* Action Toolbar */}
          <div className="flex items-center gap-3 flex-wrap">
            <div
              style={{
                background: 'var(--bg-surface)',
                border: '1px solid var(--border-strong)',
                borderRadius: 'var(--radius-sm)',
                padding: '6px 14px',
                display: 'flex',
                alignItems: 'center',
                gap: '12px',
                fontFamily: 'var(--font-mono)',
                fontSize: '12px',
              }}
            >
              <div className="flex items-center gap-2">
                <span className="status-dot status-dot-active" />
                <span style={{ color: 'var(--text-muted)' }}>TARGET:</span>
                <span style={{ color: 'var(--accent)', fontWeight: 700 }}>{serverHost}</span>
              </div>
            </div>

            <button
              className={`btn ${continuousMode ? 'btn-critical' : 'btn-outline'}`}
              style={{ fontSize: '12px', padding: '6px 14px', textTransform: 'uppercase', gap: '6px' }}
              onClick={() => setContinuousMode(!continuousMode)}
            >
              <Icon name={continuousMode ? 'stop' : 'refresh'} size={12} />
              {continuousMode ? 'Stop Loop' : 'Auto Loop'}
            </button>

            <button
              className="btn btn-outline"
              style={{ fontSize: '12px', padding: '6px 14px', textTransform: 'uppercase', gap: '6px' }}
              onClick={() => setShowCliModal(true)}
            >
              <Icon name="terminal" size={12} />
              CLI Directives
            </button>
          </div>
        </div>
      </div>

      {error && (
        <div
          className="card animate-in"
          style={{
            borderColor: 'var(--sev-critical)',
            background: 'var(--sev-critical-soft)',
            padding: '12px 18px',
          }}
        >
          <div className="flex items-center gap-3" style={{ color: 'var(--sev-critical)', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
            <Icon name="alert" size={16} />
            <strong>[ERROR]:</strong>
            <span>{error}</span>
          </div>
        </div>
      )}

      {/* Row 1: Attack Scenarios (Left) & Socket Terminal (Right) — As they were */}
      <div className="grid grid-1 lg:grid-2 gap-6" style={{ alignItems: 'stretch' }}>
        
        {/* LEFT: Attack & Baseline Scenarios (2x2 Grid) */}
        <div className="card" style={{ padding: '20px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between', height: '100%' }}>
          <div>
            <div className="flex justify-between items-center" style={{ marginBottom: '14px' }}>
              <div className="flex items-center gap-2">
                <Icon name="shield" size={16} />
                <span className="font-bold text-sm" style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  Attack &amp; Baseline Scenarios
                </span>
              </div>
              <span className="badge badge-accent text-mono" style={{ fontSize: '11px' }}>
                4 VECTORS
              </span>
            </div>

            <div className="grid grid-2 gap-3">
              {SCENARIOS.map((sc) => {
                const isSelected = selectedScenario === sc.id;
                return (
                  <div
                    key={sc.id}
                    onClick={() => handleScenarioSelect(sc.id)}
                    className={`dispatch-scenario-card ${isSelected ? 'active' : ''}`}
                    style={{
                      '--scenario-color': sc.color,
                      '--scenario-glow': sc.glow,
                    }}
                  >
                    <div>
                      <div className="flex justify-between items-center gap-2" style={{ marginBottom: '6px' }}>
                        <div className="flex items-center gap-2">
                          <span style={{ color: sc.color }}>
                            <Icon name={sc.icon} size={15} strokeWidth={2} />
                          </span>
                          <span className="font-bold text-xs" style={{ color: isSelected ? sc.color : 'var(--text-primary)' }}>
                            {sc.name}
                          </span>
                        </div>
                        <span
                          className="badge text-mono"
                          style={{
                            fontSize: '10px',
                            background: 'var(--bg-inset)',
                            borderColor: isSelected ? sc.color : 'var(--border)',
                            color: isSelected ? sc.color : 'var(--text-muted)',
                            padding: '1px 6px',
                          }}
                        >
                          :{sc.port}
                        </span>
                      </div>

                      <p className="text-xs text-secondary" style={{ margin: 0, fontSize: '11px', lineHeight: '1.4' }}>
                        {sc.shortDesc}
                      </p>
                    </div>

                    <div className="flex justify-between items-center text-xs pt-2" style={{ borderTop: '1px solid var(--border)' }}>
                      <span className={`badge ${sc.badgeClass}`} style={{ fontSize: '10px', padding: '1px 6px' }}>
                        {sc.badge}
                      </span>
                      <span style={{ color: sc.color, fontWeight: 700, fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
                        PORT {sc.port}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* RIGHT: Live Socket Terminal Window */}
        <div className="dispatch-terminal-window" style={{ height: '100%', minHeight: '360px', margin: 0 }}>
          {/* Terminal Header */}
          <div className="dispatch-terminal-header">
            <div className="flex items-center gap-2">
              <span style={{ color: 'var(--accent)', fontFamily: 'var(--font-mono)', fontSize: '13px', fontWeight: 700 }}>
                &gt;_
              </span>
              <span className="text-mono text-xs font-semibold" style={{ color: 'var(--text-primary)', letterSpacing: '0.04em' }}>
                SOCKET STREAM · {serverHost}:{activeScObj.port}
              </span>
            </div>

            <div className="flex items-center gap-2">
              <button
                className="btn btn-outline btn-sm"
                style={{ fontSize: '11px', padding: '3px 10px', gap: '4px' }}
                onClick={copyTranscriptToClipboard}
                disabled={!transcript.length}
              >
                <Icon name={copiedTranscript ? 'check' : 'copy'} size={11} />
                {copiedTranscript ? 'Copied' : 'Copy'}
              </button>
              <button
                className="btn btn-outline btn-sm"
                style={{ fontSize: '11px', padding: '3px 10px', gap: '4px' }}
                onClick={() => setTranscript([])}
                disabled={!transcript.length}
              >
                <Icon name="trash" size={11} /> Clear
              </button>
            </div>
          </div>

          {/* Screen */}
          <div ref={terminalContainerRef} className="dispatch-terminal-screen">
            {transcript.length === 0 ? (
              <div style={{ color: 'var(--text-muted)', paddingTop: '90px', textAlign: 'center', fontFamily: 'var(--font-mono)' }}>
                <div style={{ color: 'var(--accent)', marginBottom: '8px', fontSize: '13px', fontWeight: 600 }}>
                  SOCKET CONSOLE READY
                </div>
                <div style={{ fontSize: '12px' }}>
                  Select a scenario and click Transmit Scenario below to initiate live TCP dialogue.
                </div>
              </div>
            ) : (
              transcript.map((item, idx) => {
                let badgeColor = 'var(--text-muted)';
                let prefix = 'INFO';
                let textColor = 'var(--text-secondary)';

                if (item.direction === 'send') {
                  badgeColor = 'var(--accent)';
                  prefix = 'CLIENT →';
                  textColor = '#FFFFFF';
                } else if (item.direction === 'recv') {
                  badgeColor = 'var(--sev-low)';
                  prefix = '← SERVER';
                  textColor = 'var(--text-primary)';
                } else if (item.direction === 'crypto') {
                  badgeColor = 'var(--sev-clean)';
                  prefix = '[CRYPTO]';
                  textColor = '#86efac';
                } else if (item.direction === 'alert') {
                  badgeColor = 'var(--sev-critical)';
                  prefix = '[TAMPER]';
                  textColor = '#fca5a5';
                } else if (item.direction === 'error') {
                  badgeColor = 'var(--sev-critical)';
                  prefix = '[ERROR]';
                  textColor = '#ef4444';
                }

                return (
                  <div key={idx} style={{ marginBottom: '3px', wordBreak: 'break-all', display: 'flex', gap: '8px' }}>
                    <span style={{ color: 'var(--text-muted)', fontSize: '11px', flexShrink: 0 }}>{item.timestamp}</span>
                    <span
                      style={{
                        color: badgeColor,
                        fontWeight: 600,
                        flexShrink: 0,
                        minWidth: '70px',
                        fontSize: '11px',
                      }}
                    >
                      {prefix}
                    </span>
                    <span style={{ color: textColor }}>{item.text}</span>
                  </div>
                );
              })
            )}
          </div>

          {/* Footer */}
          <div className="dispatch-terminal-footer">
            <div className="flex items-center gap-2">
              <span className="status-dot status-dot-active" />
              <span>PORT {activeScObj.port}</span>
            </div>
            <div>{transcript.length} events logged</div>
          </div>
        </div>

      </div>

      {/* Row 2: Payload Parameters in Wide Rectangular Form (Full Width - Properly Utilizing Page) */}
      <div className="card" style={{ padding: '20px' }}>
        <div className="flex justify-between items-center flex-wrap gap-2" style={{ marginBottom: '16px' }}>
          <div className="flex items-center gap-2">
            <Icon name="mail" size={16} />
            <span className="font-bold text-sm" style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Payload Parameters
            </span>
          </div>
          <div className="flex gap-1 flex-wrap items-center">
            <span className="text-xs text-muted font-mono" style={{ fontSize: '11px', marginRight: '4px' }}>PRESETS:</span>
            {PRESETS.map((p) => (
              <button
                key={p.label}
                type="button"
                className="dispatch-preset-btn"
                onClick={() => {
                  setSubject(p.subject);
                  setBody(p.body);
                }}
              >
                {p.label}
              </button>
            ))}
          </div>
        </div>

        {/* 4 Parameters in a Single Horizontal Row */}
        <div className="grid grid-1 sm:grid-2 lg:grid-4 gap-3" style={{ marginBottom: '14px' }}>
          <div>
            <label className="field-label" style={{ fontSize: '11px', marginBottom: '4px' }}>Client Device Identifier</label>
            <input
              type="text"
              value={clientName}
              onChange={(e) => setClientName(e.target.value)}
              placeholder="Friend's Laptop"
              className="input text-xs"
              style={{ width: '100%' }}
            />
          </div>

          <div>
            <label className="field-label" style={{ fontSize: '11px', marginBottom: '4px' }}>Target Server IP</label>
            <input
              type="text"
              value={serverHost}
              onChange={(e) => setServerHost(e.target.value)}
              placeholder="192.168.1.40"
              className="input text-xs text-mono"
              style={{ width: '100%' }}
            />
          </div>

          <div>
            <label className="field-label" style={{ fontSize: '11px', marginBottom: '4px' }}>Sender (MAIL FROM)</label>
            <input
              type="email"
              value={sender}
              onChange={(e) => setSender(e.target.value)}
              placeholder="alice@friend-device.local"
              className="input text-xs text-mono"
              style={{ width: '100%' }}
            />
          </div>

          <div>
            <label className="field-label" style={{ fontSize: '11px', marginBottom: '4px' }}>Recipient (RCPT TO)</label>
            <input
              type="email"
              value={recipient}
              onChange={(e) => setRecipient(e.target.value)}
              placeholder="bob@securesmtp.local"
              className="input text-xs text-mono"
              style={{ width: '100%' }}
            />
          </div>
        </div>

        {/* Subject & Message Body in 2 Balanced Columns */}
        <div className="grid grid-1 lg:grid-2 gap-3" style={{ marginBottom: '14px' }}>
          <div>
            <label className="field-label" style={{ fontSize: '11px', marginBottom: '4px' }}>Subject</label>
            <input
              type="text"
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
              placeholder="Email Subject"
              className="input text-xs"
              style={{ width: '100%', marginBottom: '8px' }}
            />
            <div className="text-xs text-secondary" style={{ fontSize: '11px', lineHeight: '1.4' }}>
              RFC 5322 header envelope. Attack scenarios will inject and analyze the cryptographic envelope around this payload.
            </div>
          </div>

          <div>
            <label className="field-label" style={{ fontSize: '11px', marginBottom: '4px' }}>Message Body</label>
            <textarea
              rows={3}
              value={body}
              onChange={(e) => setBody(e.target.value)}
              placeholder="Transmission payload content..."
              className="input text-xs text-mono"
              style={{ width: '100%', resize: 'vertical', minHeight: '68px' }}
            />
          </div>
        </div>

        {/* Route Bar & Trigger */}
        <div className="dispatch-route-bar" style={{ marginTop: '6px' }}>
          <div className="flex items-center gap-2 text-xs" style={{ fontFamily: 'var(--font-mono)' }}>
            <span className="text-muted">TARGET ROUTE:</span>
            <span className="font-bold" style={{ color: activeScObj.color }}>
              {serverHost}:{activeScObj.port}
            </span>
            <span className="badge text-mono" style={{ fontSize: '10px', padding: '1px 6px', color: activeScObj.color, borderColor: activeScObj.color }}>
              {activeScObj.badge}
            </span>
          </div>

          <button
            type="button"
            className="btn btn-primary"
            disabled={loading}
            onClick={() => handleTransmit()}
            style={{
              padding: '8px 24px',
              fontSize: '12px',
              fontWeight: 600,
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
            }}
          >
            {loading ? (
              <>
                <span className="status-dot status-dot-active" />
                <span>TRANSMITTING...</span>
              </>
            ) : (
              <>
                <Icon name="send" size={14} />
                <span>Transmit Scenario →</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Row 3: Session Forensic Attribution Card (Full Width Banner Across Bottom) */}
      {lastResult && (
        <div
          className="card animate-in"
          style={{
            padding: '16px 20px',
            border: `1px solid ${activeScObj.color}`,
            boxShadow: `0 0 24px ${activeScObj.glow}`,
          }}
        >
          <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-3" style={{ marginBottom: '12px' }}>
            <div className="flex items-center gap-2">
              <span style={{ color: activeScObj.color }}><Icon name="bolt" size={16} /></span>
              <span className="font-bold text-xs text-mono" style={{ color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                Session Attributed to Telemetry Index &amp; Broadcasted to Live Ingestion Pipeline
              </span>
            </div>
            <span className="badge badge-clean text-mono" style={{ fontSize: '10px' }}>
              RECORDED
            </span>
          </div>

          <div className="grid grid-1 sm:grid-3 gap-3 text-xs text-mono" style={{ marginBottom: '12px' }}>
            <div style={{ background: 'var(--bg-inset)', padding: '10px 14px', border: '1px solid var(--border)', borderRadius: 'var(--radius-xs)' }}>
              <div className="text-muted" style={{ fontSize: '10px' }}>TARGET PORT</div>
              <div className="font-bold text-primary" style={{ marginTop: '2px', fontSize: '14px' }}>{lastResult.port}</div>
            </div>

            <div style={{ background: 'var(--bg-inset)', padding: '10px 14px', border: '1px solid var(--border)', borderRadius: 'var(--radius-xs)' }}>
              <div className="text-muted" style={{ fontSize: '10px' }}>SCENARIO ID</div>
              <div className="font-bold" style={{ color: activeScObj.color, marginTop: '2px', fontSize: '14px' }}>
                {lastResult.scenario.toUpperCase()}
              </div>
            </div>

            <div style={{ background: 'var(--bg-inset)', padding: '10px 14px', border: '1px solid var(--border)', borderRadius: 'var(--radius-xs)' }}>
              <div className="text-muted" style={{ fontSize: '10px' }}>CIPHER TUNNEL</div>
              <div className="font-bold text-primary truncate" style={{ marginTop: '2px', fontSize: '14px' }}>
                {lastResult.cipher_info || 'Cleartext (Unencrypted)'}
              </div>
            </div>
          </div>

          <div className="flex justify-between items-center pt-2 flex-wrap gap-2" style={{ borderTop: '1px solid var(--border)' }}>
            <span className="text-xs text-muted" style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
              Broadcast channel: <code className="text-accent">/ws/live</code>
            </span>

            <div className="flex gap-2">
              <Link
                to="/ingest"
                className="btn btn-outline btn-sm"
                style={{ fontSize: '11px', padding: '5px 12px' }}
              >
                Inspect in Live Ingest →
              </Link>
              <Link
                to="/sessions"
                className="btn btn-outline btn-sm"
                style={{ fontSize: '11px', padding: '5px 12px' }}
              >
                Inspect in Session Explorer →
              </Link>
            </div>
          </div>
        </div>
      )}

      {/* CLI Directives Modal */}
      {showCliModal && (
        <div className="live-modal-overlay" onClick={() => setShowCliModal(false)}>
          <div className="live-modal-container" onClick={(e) => e.stopPropagation()}>
            <div className="flex justify-between items-center" style={{ marginBottom: '16px' }}>
              <div className="flex items-center gap-2">
                <Icon name="terminal" size={18} />
                <h3 style={{ margin: 0, fontSize: '1rem', fontFamily: 'var(--font-display)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  CLI Connection Directives
                </h3>
              </div>
              <button
                className="btn btn-outline btn-sm"
                style={{ padding: '4px 8px' }}
                onClick={() => setShowCliModal(false)}
              >
                ✕
              </button>
            </div>

            <div className="flex flex-col gap-4">
              <div>
                <div className="text-xs text-muted" style={{ marginBottom: '4px', fontFamily: 'var(--font-mono)' }}>
                  1. Download Interactive Test Client
                </div>
                <div className="code-snippet-box">
                  <div className="code-snippet-header">
                    <span>CURL / WGET</span>
                  </div>
                  <div className="code-snippet-content">
                    curl -O http://{serverHost}:8000/demo_client.py
                  </div>
                </div>
              </div>

              <div>
                <div className="text-xs text-muted" style={{ marginBottom: '4px', fontFamily: 'var(--font-mono)' }}>
                  2. Run Test Client Against Server
                </div>
                <div className="code-snippet-box">
                  <div className="code-snippet-header">
                    <span>PYTHON CLI</span>
                  </div>
                  <div className="code-snippet-content">
                    python3 demo_client.py --server {serverHost}
                  </div>
                </div>
              </div>

              <div>
                <div className="text-xs text-muted" style={{ marginBottom: '4px', fontFamily: 'var(--font-mono)' }}>
                  3. Netcat Direct Probe
                </div>
                <div className="code-snippet-box">
                  <div className="code-snippet-header">
                    <span>RAW SOCKET PROBE</span>
                  </div>
                  <div className="code-snippet-content">
                    nc {serverHost} 2525
                  </div>
                </div>
              </div>

              <div>
                <div className="text-xs text-muted" style={{ marginBottom: '4px', fontFamily: 'var(--font-mono)' }}>
                  4. MitM Attacker Proxy Intercept
                </div>
                <div className="code-snippet-box">
                  <div className="code-snippet-header">
                    <span>ATTACKER PROXY</span>
                  </div>
                  <div className="code-snippet-content">
                    python3 attacker_proxy.py --listen 2525 --server {serverHost} --server-port 2526
                  </div>
                </div>
              </div>
            </div>

            <div className="flex justify-end" style={{ marginTop: '20px' }}>
              <button
                className="btn btn-primary btn-sm"
                onClick={() => setShowCliModal(false)}
              >
                Close Directives
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
