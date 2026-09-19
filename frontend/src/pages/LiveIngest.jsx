import { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  uploadPcap,
  getReportUrl,
  getLiveStatus,
  clearLiveHistory,
} from '../api/client';
import { formatBytes } from '../utils/format';
import Icon from '../components/Icon';

export default function LiveIngest() {
  const navigate = useNavigate();
  const fileInputRef = useRef(null);

  const [dragOver, setDragOver] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState('');
  const [resultJobId, setResultJobId] = useState(localStorage.getItem('sms_latest_job_id') || '');
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);
  const [wsConnected, setWsConnected] = useState(false);
  const [liveSessions, setLiveSessions] = useState([]);
  const [labStatus, setLabStatus] = useState(null);
  const [showRemoteGuide, setShowRemoteGuide] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [copiedSnippet, setCopiedSnippet] = useState('');

  useEffect(() => {
    getLiveStatus()
      .then(setLabStatus)
      .catch(() => {});

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/live`;
    let ws;
    let timer;

    function connectWs() {
      try {
        ws = new WebSocket(wsUrl);
        ws.onopen = () => {
          setWsConnected(true);
        };
        ws.onmessage = (evt) => {
          try {
            const data = JSON.parse(evt.data);
            if (data.event === 'NEW_SESSION') {
              setLiveSessions((prev) => [data, ...prev.slice(0, 29)]);
            } else if (data.event === 'DATABASE_RESET') {
              setLiveSessions([]);
            }
          } catch {}
        };
        ws.onclose = () => {
          setWsConnected(false);
          timer = setTimeout(connectWs, 3000);
        };
        ws.onerror = () => {
          setWsConnected(false);
        };
      } catch {
        setWsConnected(false);
      }
    }

    connectWs();

    return () => {
      if (timer) clearTimeout(timer);
      if (ws) ws.close();
    };
  }, []);

  const handleFileDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      setSelectedFile(file);
      setError(null);
    }
  };

  const handleFileSelect = (e) => {
    if (e.target.files && e.target.files.length > 0) {
      setSelectedFile(e.target.files[0]);
      setError(null);
    }
  };

  const handleUpload = async (fileToUpload) => {
    const file = fileToUpload || selectedFile;
    if (!file) return;

    setUploading(true);
    setError(null);
    setSuccessMsg(null);
    setUploadProgress('Reassembling TCP streams & vectorizing cryptographic handshakes…');

    try {
      const res = await uploadPcap(file);
      const jobId = res.job_id || 'audit_completed';
      setResultJobId(jobId);
      localStorage.setItem('sms_latest_job_id', jobId);
      setSuccessMsg(`PCAP trace "${file.name}" ingested successfully! Cryptographic posture updated.`);
      setSelectedFile(null);
    } catch (err) {
      console.error('Ingestion error:', err);
      setError(err.message || 'PCAP analysis failed.');
    } finally {
      setUploading(false);
      setUploadProgress('');
    }
  };

  const handleClearHistory = async () => {
    if (!window.confirm('Reset database? This clears all captured sessions to restore a clean baseline.')) return;
    setClearing(true);
    setError(null);
    try {
      await clearLiveHistory();
      setLiveSessions([]);
      setSuccessMsg('Session buffer cleared! Telemetry engine re-established at zero baseline.');
    } catch (err) {
      setError(err.message || 'Failed to clear history');
    } finally {
      setClearing(false);
    }
  };

  const copyToClipboard = (text, id) => {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text);
      setCopiedSnippet(id);
      setTimeout(() => setCopiedSnippet(''), 2000);
    }
  };

  const lanIp = labStatus?.lan_ip || '192.168.1.40';

  const PORT_LISTENERS = [
    {
      port: 2525,
      label: 'Plaintext SMTP',
      protocol: 'RFC 5321 · CLEARTEXT',
      desc: 'Unencrypted SMTP transmission with zero TLS negotiation',
      severity: 'high',
      riskTier: 'HIGH RISK',
      accentColor: '#F97316',
      accentBg: 'rgba(249, 115, 22, 0.08)',
      accentBorder: 'rgba(249, 115, 22, 0.3)',
      riskBg: 'rgba(249, 115, 22, 0.1)',
      riskBorder: 'rgba(249, 115, 22, 0.3)',
      riskColor: '#F97316',
    },
    {
      port: 2526,
      label: 'Modern TLS 1.3',
      protocol: 'TLS 1.3 · PFS SECURE',
      desc: 'Authenticated AEAD cipher suite with Perfect Forward Secrecy',
      severity: 'clean',
      riskTier: 'PRISTINE (0)',
      accentColor: '#10B981',
      accentBg: 'rgba(16, 185, 129, 0.08)',
      accentBorder: 'rgba(16, 185, 129, 0.3)',
      riskBg: 'rgba(16, 185, 129, 0.1)',
      riskBorder: 'rgba(16, 185, 129, 0.3)',
      riskColor: '#10B981',
    },
    {
      port: 2527,
      label: 'Expired / Weak Cert',
      protocol: 'TLS 1.0 · EXPIRED X.509',
      desc: 'Simulated certificate expiration and legacy 1024-bit RSA cipher',
      severity: 'medium',
      riskTier: 'MEDIUM RISK',
      accentColor: '#F59E0B',
      accentBg: 'rgba(245, 158, 11, 0.08)',
      accentBorder: 'rgba(245, 158, 11, 0.3)',
      riskBg: 'rgba(245, 158, 11, 0.1)',
      riskBorder: 'rgba(245, 158, 11, 0.3)',
      riskColor: '#F59E0B',
    },
    {
      port: 2528,
      label: 'STARTTLS Stripping',
      protocol: 'MitM DOWNGRADE PROXY',
      desc: 'Simulated adversary intercepting and stripping 250-STARTTLS',
      severity: 'critical',
      riskTier: 'CRITICAL RISK',
      accentColor: '#EF4444',
      accentBg: 'rgba(239, 68, 68, 0.08)',
      accentBorder: 'rgba(239, 68, 68, 0.3)',
      riskBg: 'rgba(239, 68, 68, 0.1)',
      riskBorder: 'rgba(239, 68, 68, 0.3)',
      riskColor: '#EF4444',
    },
  ];

  return (
    <div className="flex flex-col gap-6 max-w-7xl mx-auto">
      {/* ── EXECUTIVE HEADER ─────────────────────────────────────────────────── */}
      <div className="flex justify-between items-start flex-wrap gap-4 pb-3 border-b" style={{ borderColor: 'var(--border-subtle)' }}>
        <div>
          <div className="flex items-center gap-3 mb-1">
            <h1 className="text-xl font-bold tracking-tight" style={{ color: '#E8E8EC' }}>
              Live Ingest &amp; Telemetry Studio
            </h1>
            <span className="live-surveillance-chip">
              <span className="live-surveillance-dot" />
              <span>{wsConnected ? 'Live Sockets Active' : 'Connecting Stream…'}</span>
            </span>
          </div>
          <p className="text-secondary text-sm">
            Passive socket interception, cryptographic handshake vectorization, and offline PCAP trace analysis.
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {/* LAN Endpoint Chip */}
          <div
            className="flex items-center gap-2 px-3 py-1.5 rounded-md"
            style={{
              background: 'rgba(255, 255, 255, 0.03)',
              border: '1px solid var(--border)',
              fontFamily: 'var(--font-mono)',
              fontSize: '12px',
            }}
          >
            <span className="text-secondary">Host LAN:</span>
            <span className="text-accent font-bold">{lanIp}</span>
            <button
              type="button"
              onClick={() => copyToClipboard(lanIp, 'ip')}
              title="Copy Server IP"
              style={{ color: copiedSnippet === 'ip' ? 'var(--accent)' : 'var(--text-muted)', cursor: 'pointer', padding: '0 2px', background: 'none', border: 'none' }}
            >
              <Icon name={copiedSnippet === 'ip' ? 'check' : 'copy'} size={13} />
            </button>
          </div>

          <button
            type="button"
            className="btn btn-outline btn-sm"
            onClick={() => setShowRemoteGuide(true)}
          >
            <Icon name="terminal" size={14} />
            Connection Directives
          </button>
        </div>
      </div>

      {/* ── NOTIFICATIONS ────────────────────────────────────────────────────── */}
      {error && (
        <div
          className="card p-4 flex items-center justify-between gap-3"
          style={{
            borderColor: 'var(--sev-critical)',
            backgroundColor: 'rgba(239, 68, 68, 0.08)',
          }}
        >
          <div className="flex items-center gap-3">
            <span style={{ color: 'var(--sev-critical)' }}>
              <Icon name="alert" size={18} />
            </span>
            <div>
              <div className="text-xs font-bold font-mono" style={{ color: 'var(--sev-critical)' }}>
                [INGESTION_ERROR]
              </div>
              <div className="text-xs text-primary mt-0.5">{error}</div>
            </div>
          </div>
          <button
            type="button"
            className="btn btn-sm btn-outline"
            onClick={() => setError(null)}
            style={{ padding: '4px 10px', fontSize: '11px' }}
          >
            Dismiss
          </button>
        </div>
      )}

      {successMsg && (
        <div
          className="card p-4 flex items-center justify-between flex-wrap gap-3"
          style={{
            borderColor: 'var(--sev-clean)',
            backgroundColor: 'rgba(16, 185, 129, 0.08)',
          }}
        >
          <div className="flex items-center gap-3">
            <span style={{ color: 'var(--sev-clean)' }}>
              <Icon name="check" size={18} />
            </span>
            <div>
              <div className="text-xs font-bold font-mono" style={{ color: 'var(--sev-clean)' }}>
                [TELEMETRY_UPDATED]
              </div>
              <div className="text-xs text-primary mt-0.5">{successMsg}</div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              className="btn btn-outline btn-sm"
              onClick={() => navigate('/dashboard')}
              style={{ fontSize: '12px', padding: '5px 14px' }}
            >
              Fleet Overview →
            </button>
            <button
              type="button"
              className="btn btn-primary btn-sm"
              onClick={() => navigate('/sessions')}
              style={{ fontSize: '12px', padding: '5px 14px' }}
            >
              Inspect Sessions →
            </button>
          </div>
        </div>
      )}

      {/* ── MAIN 2-COLUMN WORKSPACE ──────────────────────────────────────────── */}
      <div className="grid grid-2 gap-6 items-start">
        {/* ── LEFT COLUMN: PCAP DROPZONE & EXECUTIVE AUDIT ────────────────────── */}
        <div className="flex flex-col gap-6">
          {/* Card 1: Packet Capture Dissection */}
          <div className="card p-5">
            <div className="flex justify-between items-start mb-2">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <Icon name="upload" size={15} />
                  <h2 className="text-sm font-semibold" style={{ color: '#E8E8EC' }}>
                    Packet Capture Ingestion
                  </h2>
                </div>
                <p className="text-secondary text-xs">
                  Offline cryptographic extraction. 100% offline dissection with zero mail payload decrypted.
                </p>
              </div>
              <span className="badge" style={{ fontSize: '10px', fontFamily: 'var(--font-mono)' }}>
                OFFLINE_ANALYSIS
              </span>
            </div>

            <input
              type="file"
              ref={fileInputRef}
              style={{ display: 'none' }}
              accept=".pcap,.pcapng,.cap"
              onChange={handleFileSelect}
            />

            {/* Premium Drag & Drop Area */}
            {!selectedFile ? (
              <div
                className={`ingest-dropzone ${dragOver ? 'drag-over' : ''}`}
                onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
                onDragLeave={() => setDragOver(false)}
                onDrop={handleFileDrop}
                onClick={() => fileInputRef.current?.click()}
              >
                <div className="ingest-dropzone-icon">
                  <Icon name="upload" size={24} />
                </div>
                <div>
                  <div className="text-primary font-semibold text-sm mb-1">
                    Drag &amp; drop PCAP trace file here, or <span className="text-accent underline">browse</span>
                  </div>
                  <div className="text-secondary text-xs">
                    Accepts standard Wireshark / tcpdump captures up to 50 MB
                  </div>
                </div>
                <div className="flex items-center gap-2 mt-1">
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono text-muted" style={{ background: '#121214', border: '1px solid #222226' }}>.pcap</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono text-muted" style={{ background: '#121214', border: '1px solid #222226' }}>.pcapng</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono text-muted" style={{ background: '#121214', border: '1px solid #222226' }}>.cap</span>
                </div>
              </div>
            ) : (
              /* Selected File Preview Box */
              <div
                className="p-4 rounded-md flex flex-col gap-3"
                style={{
                  background: 'rgba(16, 185, 129, 0.04)',
                  border: '1px solid rgba(16, 185, 129, 0.3)',
                }}
              >
                <div className="flex justify-between items-center">
                  <div className="flex items-center gap-3">
                    <div
                      className="w-10 h-10 rounded grid place-items-center"
                      style={{ background: 'rgba(16, 185, 129, 0.1)', color: 'var(--accent)' }}
                    >
                      <Icon name="file" size={20} />
                    </div>
                    <div>
                      <div className="font-semibold text-sm text-primary">
                        {selectedFile.name}
                      </div>
                      <div className="text-secondary text-xs font-mono">
                        {formatBytes(selectedFile.size)} · Ready for cryptographic dissection
                      </div>
                    </div>
                  </div>
                  <button
                    type="button"
                    className="text-secondary hover:text-primary"
                    onClick={() => setSelectedFile(null)}
                    title="Remove file"
                    style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '6px' }}
                  >
                    <Icon name="x" size={16} />
                  </button>
                </div>

                <button
                  type="button"
                  className="btn btn-primary btn-full mt-1"
                  disabled={uploading}
                  onClick={() => handleUpload()}
                >
                  {uploading ? (
                    <span className="flex items-center gap-2">
                      <Icon name="refresh" size={14} />
                      {uploadProgress || 'Vectorizing handshakes…'}
                    </span>
                  ) : (
                    `Ingest & Analyze ${selectedFile.name} →`
                  )}
                </button>
              </div>
            )}
          </div>

          {/* Card 2: Executive Compliance & Audit Reports */}
          <div className="card p-5">
            <div className="flex items-center gap-2 mb-1">
              <Icon name="download" size={15} />
              <h2 className="text-sm font-semibold" style={{ color: '#E8E8EC' }}>
                Executive Audit Reports
              </h2>
            </div>
            <p className="text-secondary text-xs mb-4">
              Export boardroom-grade compliance certification dossiers and raw cryptographic vector telemetry.
            </p>

            <div className="flex flex-col gap-2.5">
              <a
                href={getReportUrl(resultJobId || 'demo_report', 'pdf')}
                target="_blank"
                rel="noreferrer"
                className="report-export-item"
              >
                <div className="flex items-center gap-3">
                  <div
                    className="w-8 h-8 rounded grid place-items-center"
                    style={{ background: 'rgba(239, 68, 68, 0.1)', color: '#EF4444' }}
                  >
                    <Icon name="file" size={16} />
                  </div>
                  <div>
                    <div className="font-semibold text-xs text-primary">PDF Executive Briefing</div>
                    <div className="text-secondary text-[11px]">NIST SP 800-52r2 certification brief with executive scorecard</div>
                  </div>
                </div>
                <div className="flex items-center gap-1.5 text-xs text-secondary font-mono">
                  <span>Export</span>
                  <Icon name="download" size={13} />
                </div>
              </a>

              <a
                href={getReportUrl(resultJobId || 'demo_report', 'html')}
                target="_blank"
                rel="noreferrer"
                className="report-export-item"
              >
                <div className="flex items-center gap-3">
                  <div
                    className="w-8 h-8 rounded grid place-items-center"
                    style={{ background: 'rgba(56, 189, 248, 0.1)', color: '#38BDF8' }}
                  >
                    <Icon name="globe" size={16} />
                  </div>
                  <div>
                    <div className="font-semibold text-xs text-primary">HTML Interactive Dossier</div>
                    <div className="text-secondary text-[11px]">Interactive session replay with cipher suites and certificate chains</div>
                  </div>
                </div>
                <div className="flex items-center gap-1.5 text-xs text-secondary font-mono">
                  <span>Export</span>
                  <Icon name="download" size={13} />
                </div>
              </a>

              <a
                href={getReportUrl(resultJobId || 'demo_report', 'json')}
                target="_blank"
                rel="noreferrer"
                className="report-export-item"
              >
                <div className="flex items-center gap-3">
                  <div
                    className="w-8 h-8 rounded grid place-items-center"
                    style={{ background: 'rgba(16, 185, 129, 0.1)', color: 'var(--accent)' }}
                  >
                    <Icon name="code" size={16} />
                  </div>
                  <div>
                    <div className="font-semibold text-xs text-primary">JSON Telemetry Stream</div>
                    <div className="text-secondary text-[11px]">Vectorized security telemetry schema for enterprise SIEM integration</div>
                  </div>
                </div>
                <div className="flex items-center gap-1.5 text-xs text-secondary font-mono">
                  <span>Export</span>
                  <Icon name="download" size={13} />
                </div>
              </a>
            </div>
          </div>
        </div>

        {/* ── RIGHT COLUMN: LISTENERS & REAL-TIME STREAM ───────────────────────── */}
        <div className="flex flex-col gap-6">
          {/* Card 1: Multi-Port Socket Listeners Matrix */}
          <div className="card p-5">
            <div className="flex justify-between items-start mb-3 flex-wrap gap-2">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-accent">
                    <Icon name="server" size={16} />
                  </span>
                  <h2 className="text-sm font-semibold tracking-tight" style={{ color: '#E8E8EC' }}>
                    Multi-Port Socket Listeners
                  </h2>
                </div>
                <p className="text-secondary text-xs">
                  Passive local background daemons listening on interface <code className="font-mono text-accent">0.0.0.0</code>:
                </p>
              </div>
              <div className="socket-active-pill">
                <span className="socket-pulse-led" />
                <span>4 DAEMONS READY</span>
              </div>
            </div>

            <div className="flex flex-col gap-2.5 my-3">
              {PORT_LISTENERS.map((item) => (
                <div
                  key={item.port}
                  className="socket-listener-card"
                  style={{ '--socket-accent': item.accentColor }}
                >
                  <div className="flex items-center gap-3.5 min-w-0 flex-1">
                    {/* Hardware Socket Port Badge */}
                    <div
                      className="socket-port-badge"
                      style={{
                        borderColor: item.accentBorder,
                        background: item.accentBg,
                      }}
                    >
                      <span className="socket-port-tag">PORT</span>
                      <span className="socket-port-num" style={{ color: item.accentColor }}>
                        {item.port}
                      </span>
                    </div>

                    {/* Metadata, Protocol Tag & Description */}
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        <span className="text-xs font-bold text-primary tracking-tight">
                          {item.label}
                        </span>
                        <span className="socket-protocol-tag">
                          {item.protocol}
                        </span>
                      </div>
                      <div className="text-xs text-secondary leading-snug">
                        {item.desc}
                      </div>
                    </div>
                  </div>

                  {/* Status & Severity Controls */}
                  <div className="flex items-center gap-2.5 flex-shrink-0">
                    <span
                      className="socket-risk-pill"
                      style={{
                        color: item.riskColor,
                        background: item.riskBg,
                        border: `1px solid ${item.riskBorder}`,
                      }}
                    >
                      {item.riskTier}
                    </span>
                    <div className="socket-active-pill">
                      <span className="socket-pulse-led" />
                      <span>ONLINE</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            <div className="socket-pipeline-footer">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-accent">
                  <Icon name="activity" size={13} />
                </span>
                <span className="text-[11px] font-mono font-bold text-accent tracking-wider uppercase">
                  In-Memory Vectorization Pipeline
                </span>
              </div>
              <p className="text-xs text-secondary leading-relaxed">
                Incoming TCP handshakes on ports 2525–2528 are mirrored into memory, parsed for TLS version and cipher negotiations, evaluated by the Isolation Forest ML engine, and broadcasted to the feed below.
              </p>
            </div>
          </div>

          {/* Card 2: Captured Telemetry Stream */}
          <div className="card p-5">
            <div className="flex justify-between items-center mb-3">
              <div className="flex items-center gap-2">
                <Icon name="radar" size={15} />
                <h2 className="text-sm font-semibold" style={{ color: '#E8E8EC' }}>
                  Captured Sessions Feed
                </h2>
                {liveSessions.length > 0 && (
                  <span className="badge badge-accent text-[10px] font-mono">
                    {liveSessions.length} CAPTURED
                  </span>
                )}
              </div>

              {liveSessions.length > 0 && (
                <button
                  type="button"
                  className="btn btn-sm btn-outline text-xs"
                  onClick={() => setLiveSessions([])}
                  style={{ padding: '3px 10px', fontSize: '11px' }}
                >
                  Clear Feed
                </button>
              )}
            </div>

            {liveSessions.length > 0 ? (
              <div className="flex flex-col gap-2 max-h-[320px] overflow-y-auto pr-1">
                {liveSessions.map((sess, idx) => (
                  <div
                    key={`${sess.session_id}-${idx}`}
                    className="flex justify-between items-center p-3 rounded-md transition-all"
                    style={{
                      background: 'rgba(255, 255, 255, 0.02)',
                      border: '1px solid var(--border)',
                    }}
                  >
                    <div className="flex items-center gap-3">
                      <div
                        className="w-2 h-8 rounded-full"
                        style={{
                          background: sess.risk_score >= 75 ? 'var(--sev-critical)' : sess.risk_score >= 50 ? 'var(--sev-high)' : sess.risk_score >= 25 ? 'var(--sev-medium)' : 'var(--sev-clean)',
                        }}
                      />
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-xs text-primary font-mono">
                            #{sess.session_id} · {sess.scenario || 'LIVE_FLOW'}
                          </span>
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-[#18181B] text-secondary">
                            {sess.protocol}
                          </span>
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-[#18181B] text-accent">
                            {sess.tls_mode}
                          </span>
                        </div>
                        <div className="text-muted text-[11px] font-mono mt-0.5">
                          {sess.src_ip}:{sess.src_port} ➔ {sess.dst_ip}:{sess.dst_port}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-3">
                      <div className="text-right">
                        <div className="text-[10px] text-muted font-mono">RISK SCORE</div>
                        <div
                          className="font-bold text-xs font-mono"
                          style={{
                            color: sess.risk_score >= 75 ? 'var(--sev-critical)' : sess.risk_score >= 50 ? 'var(--sev-high)' : 'var(--sev-clean)',
                          }}
                        >
                          {sess.risk_score} / 100
                        </div>
                      </div>
                      <button
                        type="button"
                        className="btn btn-outline btn-sm"
                        style={{ fontSize: '11px', padding: '4px 10px' }}
                        onClick={() => navigate(`/dashboard/sessions/${sess.host_id || ''}`)}
                      >
                        Inspect →
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              /* High-Tech Radar Awaiting State */
              <div className="feed-awaiting-container">
                <div className="feed-radar-halo">
                  <Icon name="radar" size={22} className="animate-pulse" />
                </div>
                <div>
                  <div className="feed-awaiting-title">
                    Awaiting Incoming Mail Traffic
                  </div>
                  <p className="feed-awaiting-desc">
                    Passive listeners bound to <code className="font-mono text-accent font-semibold">{lanIp}:2525–2528</code>. Run a test client to view real-time handshakes.
                  </p>
                </div>
                <button
                  type="button"
                  className="btn btn-outline btn-sm"
                  onClick={() => setShowRemoteGuide(true)}
                >
                  <Icon name="terminal" size={13} />
                  <span>Open Test Harness Commands</span>
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── SYSTEM MAINTENANCE / ENVIRONMENT BASELINE ────────────────────────── */}
      <div
        className="card p-4 flex justify-between items-center flex-wrap gap-3 mt-2"
        style={{
          background: 'rgba(13, 13, 14, 0.6)',
          border: '1px solid var(--border)',
        }}
      >
        <div className="flex items-center gap-3">
          <div
            className="w-8 h-8 rounded grid place-items-center"
            style={{ background: 'rgba(255, 255, 255, 0.04)', color: 'var(--text-muted)' }}
          >
            <Icon name="shield" size={15} />
          </div>
          <div>
            <div className="font-semibold text-xs text-primary">System Telemetry Buffer &amp; Maintenance</div>
            <div className="text-secondary text-[11px]">
              Clears historical session database and re-establishes an untainted zero-traffic posture for clean demonstrations.
            </div>
          </div>
        </div>

        <button
          type="button"
          className="btn btn-outline btn-sm"
          onClick={handleClearHistory}
          disabled={clearing}
          style={{
            color: '#F87171',
            borderColor: 'rgba(239, 68, 68, 0.25)',
          }}
        >
          <Icon name="trash" size={13} />
          {clearing ? 'Clearing Database…' : 'Reset Database & Clear History'}
        </button>
      </div>

      {/* ── CONNECTION DIRECTIVES MODAL ──────────────────────────────────────── */}
      {showRemoteGuide && (
        <div className="live-modal-overlay" onClick={() => setShowRemoteGuide(false)}>
          <div className="live-modal-container" onClick={(e) => e.stopPropagation()}>
            <div className="flex justify-between items-start mb-4 pb-3 border-b" style={{ borderColor: 'var(--border)' }}>
              <div className="flex items-center gap-3">
                <div
                  className="w-9 h-9 rounded-lg grid place-items-center"
                  style={{ background: 'rgba(16, 185, 129, 0.1)', color: 'var(--accent)' }}
                >
                  <Icon name="terminal" size={18} />
                </div>
                <div>
                  <h3 className="text-md font-bold text-primary">Client Connection Directives</h3>
                  <p className="text-secondary text-xs">
                    Send test mail flows from any laptop or machine connected to the same LAN or Wi-Fi.
                  </p>
                </div>
              </div>
              <button
                type="button"
                className="text-secondary hover:text-primary"
                onClick={() => setShowRemoteGuide(false)}
                style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '4px' }}
              >
                <Icon name="x" size={18} />
              </button>
            </div>

            <div className="flex flex-col gap-4">
              {/* Option A: Python Test Client */}
              <div>
                <div className="flex justify-between items-center mb-1">
                  <div className="font-semibold text-xs text-primary font-mono">
                    OPTION 1: AUTOMATED PYTHON TEST CLIENT
                  </div>
                  <span className="text-[10px] text-accent font-mono">RECOMMENDED</span>
                </div>
                <p className="text-secondary text-xs mb-2">
                  Downloads and executes the automated SMTP test client against your sensor IP (<code>{lanIp}</code>):
                </p>

                <div className="code-snippet-box">
                  <div className="code-snippet-header">
                    <span>bash / terminal</span>
                    <button
                      type="button"
                      onClick={() => copyToClipboard(`curl -O http://${lanIp}:8000/demo_client.py\npython3 demo_client.py --server ${lanIp} --port 2526`, 'py-tls')}
                      style={{ color: copiedSnippet === 'py-tls' ? 'var(--accent)' : 'inherit', cursor: 'pointer', background: 'none', border: 'none' }}
                    >
                      {copiedSnippet === 'py-tls' ? 'Copied!' : 'Copy'}
                    </button>
                  </div>
                  <pre className="code-snippet-content">
{`# 1. Download automated script from this sensor
curl -O http://${lanIp}:8000/demo_client.py

# 2. Modern Hardened TLS 1.3 test (Port 2526) -> Clean 0 Risk
python3 demo_client.py --server ${lanIp} --port 2526

# 3. STARTTLS Stripping Attack test (Port 2528) -> Critical 92 Risk
python3 demo_client.py --server ${lanIp} --port 2528

# 4. Cleartext test (Port 2525) -> High Risk
python3 demo_client.py --server ${lanIp} --port 2525`}
                  </pre>
                </div>
              </div>

              {/* Option B: Netcat Shell */}
              <div>
                <div className="flex justify-between items-center mb-1">
                  <div className="font-semibold text-xs text-primary font-mono">
                    OPTION 2: ZERO-INSTALL NETCAT (POSIX)
                  </div>
                  <span className="text-[10px] text-muted font-mono">NO PYTHON REQUIRED</span>
                </div>
                <p className="text-secondary text-xs mb-2">
                  Transmit raw SMTP command envelopes directly using built-in terminal utilities:
                </p>

                <div className="code-snippet-box">
                  <div className="code-snippet-header">
                    <span>bash / nc</span>
                    <button
                      type="button"
                      onClick={() => copyToClipboard(`nc ${lanIp} 2525 << 'EOF'\nHELO client-device.local\nMAIL FROM:<alice@company.com>\nRCPT TO:<bob@company.com>\nDATA\nConfidential credentials transmitted in cleartext...\n.\nQUIT\nEOF`, 'nc')}
                      style={{ color: copiedSnippet === 'nc' ? 'var(--accent)' : 'inherit', cursor: 'pointer', background: 'none', border: 'none' }}
                    >
                      {copiedSnippet === 'nc' ? 'Copied!' : 'Copy'}
                    </button>
                  </div>
                  <pre className="code-snippet-content">
{`nc ${lanIp} 2525 << 'EOF'
HELO client-device.local
MAIL FROM:<alice@company.com>
RCPT TO:<bob@company.com>
DATA
Confidential credentials transmitted in cleartext...
.
QUIT
EOF`}
                  </pre>
                </div>
              </div>
            </div>

            <div className="flex justify-end mt-5 pt-3 border-t" style={{ borderColor: 'var(--border)' }}>
              <button
                type="button"
                className="btn btn-primary btn-sm"
                onClick={() => setShowRemoteGuide(false)}
                style={{ padding: '6px 18px', fontSize: '13px' }}
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
