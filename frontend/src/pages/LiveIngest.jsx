import { usePilot } from '../context/PilotContext';
import useClipboard from '../hooks/useClipboard';
import { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  uploadPcap,
  getAnalysisStatus,
  downloadReport,
  getAccessToken,
  getLiveSocketUrl,
  getLiveStatus,
  getSessions,
  clearLiveHistory,
} from '../api/client';
import { formatBytes } from '../utils/format';
import Icon from '../components/Icon';
import Modal from '../components/Modal';
import Notice from '../components/Notice';
import { getTierColor, getTierFromScore } from '../utils/colors';
import { riskValue, validateCapture } from '../utils/telemetry';
import { waitForAnalysis } from '../utils/analysis';

export default function LiveIngest() {
  const { canUseLab } = usePilot();
  const { copyText, clipboardError } = useClipboard();
  const navigate = useNavigate();
  const fileInputRef = useRef(null);
  const analysisController = useRef(null);
  const [pendingJobId, setPendingJobId] = useState('');
  useEffect(() => () => analysisController.current?.abort(), []);

  const [dragOver, setDragOver] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState('');
  const [resultJobId, setResultJobId] = useState('');
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);
  const [wsConnected, setWsConnected] = useState(false);
  const [liveSessions, setLiveSessions] = useState([]);
  const [labStatus, setLabStatus] = useState(null);
  const [statusError, setStatusError] = useState('');
  const [statusRetry, setStatusRetry] = useState(0);
  useEffect(() => {
    let active = true;
    if (!canUseLab) return;
    getLiveStatus().then(status => { if (active) { setLabStatus(status); setStatusError(''); } }).catch(() => { if (active) setStatusError('Listener status is unavailable. Check the API connection.'); });
    return () => { active = false; };
  }, [statusRetry, canUseLab]);
  useEffect(() => {
    const controller = new AbortController();
    let saved;
    try { saved = localStorage.getItem('sms_latest_job_id'); } catch { return; }
    if (saved) getAnalysisStatus(saved, { signal: controller.signal }).then(job => {
      if (!controller.signal.aborted && job.status === 'done') setResultJobId(saved);
    }).catch(() => {});
    return () => controller.abort();
  }, []);
  const [showRemoteGuide, setShowRemoteGuide] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [copiedSnippet, setCopiedSnippet] = useState('');

  useEffect(() => {
    const wsUrl = getLiveSocketUrl();
    let ws;
    let timer;
    let disposed = false;

    let refreshId = 0;
    async function refreshSessions() {
      const id = ++refreshId;
      try {
        const sessions = await getSessions(30);
        if (!disposed && id === refreshId) {
          setLiveSessions(sessions.map(session => ({...session, session_id: session.id})));
          setStatusError('');
        }
      } catch (failure) {
        if (!disposed) setStatusError('Recent sessions may be stale. ' + failure.message);
      }
    }
    function connectWs() {
      if (disposed) return;
      try {
        ws = new WebSocket(wsUrl);
        ws.onopen = async () => {
          try {
            const token = await getAccessToken();
            if (!disposed && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ token }));
          } catch { ws.close(); }
        };
        ws.onmessage = (evt) => {
          try {
            const data = JSON.parse(evt.data);
            if (data.event === 'AUTHENTICATED') {
              setWsConnected(true);
              refreshSessions();
            } else if (data.event === 'ASSESSMENT_UPDATED') {
              refreshSessions();
            } else if (data.event === 'NEW_SESSION') {
              setLiveSessions((prev) => [data, ...prev.slice(0, 29)]);
            } else if (data.event === 'DATABASE_RESET') {
              refreshSessions();
            }
          } catch {}
        };
        ws.onclose = () => {
          setWsConnected(false);
          if (!disposed) timer = setTimeout(connectWs, 3000);
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
      disposed = true;
      if (timer) clearTimeout(timer);
      if (ws) ws.close();
    };
  }, []);

  const selectCapture = (file) => {
    if (uploading) return;
    const validation = validateCapture(file);
    setError(validation || null);
    setSuccessMsg(null);
    setSelectedFile(validation ? null : file);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };
  const handleFileDrop = (event) => {
    event.preventDefault();
    setDragOver(false);
    if (event.dataTransfer.files?.[0]) selectCapture(event.dataTransfer.files[0]);
  };
  const handleFileSelect = (event) => {
    if (event.target.files?.[0]) selectCapture(event.target.files[0]);
  };
  const finishAnalysis = async (jobId, signal) => {
    await waitForAnalysis(jobId, {
      getStatus: getAnalysisStatus, signal,
      onStatus: status => setUploadProgress(status === 'queued' ? 'Capture queued for analysis…' : 'Analyzing sessions and certificates…'),
    });
    setResultJobId(jobId);
    setPendingJobId('');
    try { localStorage.setItem('sms_latest_job_id', jobId); } catch { /* Reports remain available for this visit. */ }
    setSuccessMsg('Analysis complete. Sessions and reports are ready to inspect.');
    setSelectedFile(null);
  };
  const handleUpload = async () => {
    if (!selectedFile || uploading) return;
    const validation = validateCapture(selectedFile);
    if (validation) { setError(validation); return; }
    analysisController.current?.abort();
    const controller = new AbortController();
    analysisController.current = controller;
    setUploading(true); setError(null); setSuccessMsg(null);
    setUploadProgress('Uploading capture…');
    try {
      const result = await uploadPcap(selectedFile);
      if (controller.signal.aborted) return;
      if (!result.job_id) throw new Error('The server did not return an analysis job. Try uploading again.');
      setPendingJobId(result.job_id);
      await finishAnalysis(result.job_id, controller.signal);
    } catch (err) {
      if (!controller.signal.aborted) setError(err.message || 'Capture analysis failed.');
    } finally {
      if (!controller.signal.aborted) { setUploading(false); setUploadProgress(''); }
    }
  };
  const checkPendingAnalysis = async () => {
    if (!pendingJobId || uploading) return;
    const controller = new AbortController();
    analysisController.current = controller;
    setUploading(true); setError(null);
    try { await finishAnalysis(pendingJobId, controller.signal); }
    catch (err) { if (!controller.signal.aborted) setError(err.message); }
    finally { if (!controller.signal.aborted) { setUploading(false); setUploadProgress(''); } }
  };

  const handleClearHistory = async () => {
    if (!window.confirm('Clear the controlled mail lab’s session history?')) return;
    setClearing(true);
    setError(null);
    try {
      await clearLiveHistory();
      const sessions = await getSessions(30);
      setLiveSessions(sessions.map(session => ({...session, session_id: session.id})));
      setSuccessMsg('Controlled lab history cleared.');
    } catch (err) {
      setError(err.message || 'Failed to clear history');
    } finally {
      setClearing(false);
    }
  };

  const copyToClipboard = (text, id) => {
    copyText(text, () => { setCopiedSnippet(id); setTimeout(() => setCopiedSnippet(''), 2000); });
  };

  const lanIp = labStatus?.lan_ip || window.location.hostname;

  const PORT_LISTENERS = [
    {
      port: 2525,
      label: 'Plaintext SMTP',
      protocol: 'RFC 5321 · CLEARTEXT',
      desc: 'Unencrypted SMTP transmission with zero TLS negotiation',
      severity: 'high',
      riskTier: 'HIGH RISK',
      accentColor: 'var(--sev-high)',
      accentBg: 'rgba(249, 115, 22, 0.08)',
      accentBorder: 'rgba(249, 115, 22, 0.3)',
      riskBg: 'rgba(249, 115, 22, 0.1)',
      riskBorder: 'rgba(249, 115, 22, 0.3)',
      riskColor: 'var(--sev-high)',
    },
    {
      port: 2526,
      label: 'Modern TLS 1.3',
      protocol: 'TLS 1.3 · PFS SECURE',
      desc: 'Authenticated AEAD cipher suite with Perfect Forward Secrecy',
      severity: 'clean',
      riskTier: 'PRISTINE (0)',
      accentColor: 'var(--accent)',
      accentBg: 'rgba(16, 185, 129, 0.08)',
      accentBorder: 'rgba(16, 185, 129, 0.3)',
      riskBg: 'rgba(16, 185, 129, 0.1)',
      riskBorder: 'rgba(16, 185, 129, 0.3)',
      riskColor: 'var(--accent)',
    },
    {
      port: 2527,
      label: 'Expired / Weak Cert',
      protocol: 'TLS 1.0 · EXPIRED X.509',
      desc: 'Simulated certificate expiration and legacy 1024-bit RSA cipher',
      severity: 'medium',
      riskTier: 'MEDIUM RISK',
      accentColor: 'var(--sev-medium)',
      accentBg: 'rgba(245, 158, 11, 0.08)',
      accentBorder: 'rgba(245, 158, 11, 0.3)',
      riskBg: 'rgba(245, 158, 11, 0.1)',
      riskBorder: 'rgba(245, 158, 11, 0.3)',
      riskColor: 'var(--sev-medium)',
    },
    {
      port: 2528,
      label: 'STARTTLS Stripping',
      protocol: 'MitM DOWNGRADE PROXY',
      desc: 'Simulated adversary intercepting and stripping 250-STARTTLS',
      severity: 'critical',
      riskTier: 'CRITICAL RISK',
      accentColor: 'var(--sev-critical)',
      accentBg: 'rgba(239, 68, 68, 0.08)',
      accentBorder: 'rgba(239, 68, 68, 0.3)',
      riskBg: 'rgba(239, 68, 68, 0.1)',
      riskBorder: 'rgba(239, 68, 68, 0.3)',
      riskColor: 'var(--sev-critical)',
    },
  ];

  return (
    <div className="simple-page">
      <header className="simple-heading">
        <div><h1>Capture &amp; live sessions</h1><p>Upload a capture or watch incoming test traffic.</p></div>
        {canUseLab && <button className="btn btn-outline" onClick={() => setShowRemoteGuide(true)}>Connection guide</button>}
      </header>
      {clipboardError && <Notice>{clipboardError}</Notice>}
      {statusError && <Notice onRetry={() => setStatusRetry(value => value + 1)}>{statusError}</Notice>}
      {error && <Notice>{error}</Notice>}
      {successMsg && <Notice tone="info">{successMsg}</Notice>}
      {pendingJobId && !uploading && <Notice tone="info" onRetry={checkPendingAnalysis}>Analysis pending. Check its status.</Notice>}
      <div className="simple-columns">
        <section className="card simple-stack">
          <h2>Upload capture</h2>
          <input type="file" ref={fileInputRef} hidden accept=".pcap,.pcapng" aria-label="Choose packet capture" disabled={uploading} onChange={handleFileSelect} />
          {!selectedFile ? <button
            type="button" className={`ingest-dropzone ${dragOver ? 'drag-over' : ''}`} disabled={uploading}
            onDragOver={event => { event.preventDefault(); setDragOver(true); }} onDragLeave={() => setDragOver(false)}
            onDrop={handleFileDrop} onClick={() => fileInputRef.current?.click()}
          ><Icon name="upload" size={24} /><strong>Drop a capture or browse</strong><span className="text-secondary text-sm">PCAP or PCAPNG · up to 25 MB</span></button> : <div className="simple-stack">
            <div className="simple-row"><div className="capture-filename"><strong>{selectedFile.name}</strong><small>{formatBytes(selectedFile.size)}</small></div><button className="btn btn-outline" disabled={uploading} onClick={() => setSelectedFile(null)}>Remove</button></div>
            <button className="btn btn-primary" disabled={uploading} onClick={handleUpload}>{uploading ? 'Analyzing…' : 'Analyze capture'}</button>
          </div>}
          {uploading && <p role="status" className="text-secondary text-sm">{uploadProgress || 'Checking analysis…'}</p>}
          <div className="simple-divider simple-stack">
            <div className="simple-row"><h2>Reports</h2>{resultJobId && <button className="text-action" onClick={() => navigate('/dashboard/sessions')}>View sessions →</button>}</div>
            {resultJobId ? <div className="ui-toolbar">{['pdf', 'html', 'json'].map(format => <button className="btn btn-outline" onClick={() => downloadReport(resultJobId, format).catch(error => setError(error.message))} key={format}><Icon name="download" size={14} />{format.toUpperCase()}</button>)}</div> : <p className="text-secondary text-sm">Available after your first completed analysis.</p>}
          </div>
        </section>
        <section className="card simple-stack">
          <div className="simple-row"><h2>Live sessions</h2><span className="text-sm text-secondary">{wsConnected ? 'Connected' : 'Reconnecting…'}</span></div>
          {liveSessions.length ? <>
            <div className="live-session-list">{liveSessions.map((session, index) => <div className="simple-row live-session-row" key={`${session.session_id}-${index}`}>
              <div><strong>Session #{session.session_id}</strong><small>{session.src_ip} → {session.dst_ip}</small></div>
              <span className="live-risk" style={{ color: getTierColor(riskValue(session.risk_score) == null ? 'info' : getTierFromScore(session.risk_score)) }}>{riskValue(session.risk_score) ?? '—'}<small>/100</small></span>
              <button className="btn btn-outline" onClick={() => navigate(`/dashboard/sessions/${session.host_id || ''}?session=${session.session_id}`)}>Inspect</button>
            </div>)}</div>
            <button className="text-action" onClick={() => setLiveSessions([])}>Clear feed</button>
          </> : <div className="simple-empty"><p>No new sessions yet.</p><button className="btn btn-outline" onClick={() => navigate('/dashboard/operations')}>View monitoring agents</button></div>}
          {canUseLab && <details className="simple-details">
            <summary>Listener setup <span>{labStatus?.is_running ? 'Running' : labStatus ? 'Stopped' : 'Unavailable'}</span></summary>
            <div className="simple-stack"><div className="simple-row"><code>{lanIp}</code><button className="text-action" onClick={() => copyToClipboard(lanIp, 'address')}>{copiedSnippet === 'address' ? 'Copied' : 'Copy address'}</button></div>
              <dl className="simple-definition-list">{PORT_LISTENERS.map(listener => <div key={listener.port}><dt>{listener.label}</dt><dd>{listener.port}</dd></div>)}</dl>
            </div>
          </details>}
        </section>
      </div>
      {canUseLab && <details className="simple-details"><summary>Manage history</summary><div className="simple-row"><p className="text-secondary text-sm">Clear the controlled mail lab’s captured sessions.</p><button className="btn btn-outline" disabled={clearing || uploading} onClick={handleClearHistory}>{clearing ? 'Clearing…' : 'Clear history'}</button></div></details>}
      {showRemoteGuide && (
        <Modal label="Client connection guide" onClose={() => setShowRemoteGuide(false)}>
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
                  <h3 className="text-md font-bold text-primary">Connection guide</h3>
                  <p className="text-secondary text-xs">
                    Send test mail flows from any laptop or machine connected to the same LAN or Wi-Fi.
                  </p>
                </div>
              </div>
              <button
                type="button"
                className="text-secondary hover:text-primary"
                onClick={() => setShowRemoteGuide(false)}
                aria-label="Close connection guide"
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
                aria-label="Close connection guide"
                style={{ padding: '6px 18px', fontSize: '13px' }}
              >
                Close Directives
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}
