/*
  DIRECTION CONTRACT
  THESIS: A command-line instrument that earns trust through demonstrated
  competence, not marketing rhetoric. The landing surface proves the product
  by showing it working, not by describing what it does.
  OWN-WORLD: Obsidian Stealth — #050505 canvas, #0D0D0E surface, emerald
  accent #10B981, Exon headings, JetBrains Mono for data. Elevation through
  subtle border luminosity, not shadow. Motion is state-driven, never decorative.
  STORY: The visitor sees the analysis engine working, understands the depth
  of cryptographic inspection, and enters the console.
  FIRST VIEWPORT: Full-height instrument panel. Left: product name at
  comfortable scale, one sentence of mechanism, primary action. Right:
  a live terminal rendering real analysis output, proving the claim.
  FORM: Instrument documentation — precision, evidence, earned authority.
  FINISH: unreviewed and undocumented is unfinished.
*/

import { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import Logo from '../components/Logo';
import Icon from '../components/Icon';
import { useAuth } from '../context/AuthContext';

/* ── Intersection Observer ──────────────────────────────────────────────── */
function useInView(opts = {}) {
  const ref = useRef(null);
  const [visible, setVisible] = useState(false);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const obs = new IntersectionObserver(
      ([e]) => { if (e.isIntersecting) { setVisible(true); obs.disconnect(); } },
      { threshold: 0.12, ...opts }
    );
    obs.observe(el);
    return () => obs.disconnect();
  }, []);
  return [ref, visible];
}

/* ── Terminal with real analysis output ─────────────────────────────────── */
const TERMINAL_FEED = [
  { t: 'cmd', v: '$ secure-smtp analyze --pcap corporate-mail.pcap' },
  { t: 'dim', v: '' },
  { t: 'dim', v: 'Ingesting 14,832 packets · 3 TCP streams detected' },
  { t: 'dim', v: 'Protocol: SMTP (STARTTLS), IMAP (TLS 1.2), POP3 (plaintext)' },
  { t: 'dim', v: '' },
  { t: 'grn', v: '  ✓  TLS 1.3 handshake · mail.corp.io:465' },
  { t: 'grn', v: '     Cipher: TLS_AES_256_GCM_SHA384 · ECDHE x25519' },
  { t: 'grn', v: '     JA3: cd08e31494f9531f560d64c695473da9' },
  { t: 'dim', v: '' },
  { t: 'ylw', v: '  ⚠  TLS 1.0 negotiated · legacy-mx.corp.io:587' },
  { t: 'ylw', v: '     Cipher: TLS_RSA_WITH_AES_128_CBC_SHA (CBC mode)' },
  { t: 'ylw', v: '     NIST SP 800-52r2 §3.1 — MUST NOT use TLS 1.0' },
  { t: 'dim', v: '' },
  { t: 'red', v: '  ✖  CRITICAL · Plaintext AUTH PLAIN on port 110' },
  { t: 'red', v: '     Credentials transmitted without encryption' },
  { t: 'red', v: '     RFC 8314 §3.3 — Cleartext is obsolete' },
  { t: 'dim', v: '' },
  { t: 'dim', v: '─────────────────────────────────────────────────' },
  { t: 'wht', v: '  Risk Score        78.4 / 100    HIGH' },
  { t: 'wht', v: '  Hosts                 3    Sessions          14' },
  { t: 'wht', v: '  Findings              7    Compliance    FAIL' },
  { t: 'dim', v: '─────────────────────────────────────────────────' },
  { t: 'dim', v: '' },
  { t: 'grn', v: '  Report saved → audit_2026-09-18.pdf' },
];

const TERM_COLORS = {
  cmd: '#10B981',
  grn: '#10B981',
  ylw: '#FACC15',
  red: '#EF4444',
  wht: '#E8E8EC',
  dim: '#4A4A52',
};

function LiveTerminal() {
  const [visibleCount, setVisibleCount] = useState(1);
  const containerRef = useRef(null);

  useEffect(() => {
    const timer = setInterval(() => {
      setVisibleCount(prev => {
        if (prev < TERMINAL_FEED.length) {
          return prev + 1;
        }
        clearInterval(timer);
        return prev;
      });
    }, 280);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [visibleCount]);

  const renderedLines = TERMINAL_FEED.slice(0, visibleCount);

  return (
    <div className="lp-terminal">
      <div className="lp-terminal-chrome">
        <div className="lp-terminal-dots">
          <span style={{ background: '#EF4444' }} />
          <span style={{ background: '#FACC15' }} />
          <span style={{ background: '#10B981' }} />
        </div>
        <span className="lp-terminal-label">secure-smtp — live analysis</span>
      </div>
      <div className="lp-terminal-output" ref={containerRef}>
        {renderedLines.map((l, i) => (
          <div key={i} className="lp-term-line" style={{ color: (l && l.t && TERM_COLORS[l.t]) || TERM_COLORS.dim }}>
            {(l && l.v) || '\u00A0'}
          </div>
        ))}
        {visibleCount < TERMINAL_FEED.length && <span className="lp-caret">▊</span>}
      </div>
    </div>
  );
}

/* ── Architecture step ──────────────────────────────────────────────────── */
function PipelineStep({ icon, label, sub, delay, active }) {
  const [ref, vis] = useInView();
  return (
    <div
      ref={ref}
      className={`lp-pipe-step ${vis ? 'in' : ''}`}
      style={{ transitionDelay: `${delay}ms` }}
    >
      <div className={`lp-pipe-icon ${active ? 'lp-pipe-active' : ''}`}>
        <Icon name={icon} size={18} />
      </div>
      <span className="lp-pipe-label">{label}</span>
      <span className="lp-pipe-sub">{sub}</span>
    </div>
  );
}

/* ── Capability row ─────────────────────────────────────────────────────── */
function Capability({ icon, title, body, idx: i }) {
  const [ref, vis] = useInView();
  return (
    <div
      ref={ref}
      className={`lp-cap ${vis ? 'in' : ''}`}
      style={{ transitionDelay: `${i * 80}ms` }}
    >
      <div className="lp-cap-icon">
        <Icon name={icon} size={18} />
      </div>
      <div className="lp-cap-text">
        <h3>{title}</h3>
        <p>{body}</p>
      </div>
    </div>
  );
}

/* ════════════════════════════════════════════════════════════════════════════
   LANDING PAGE
   ════════════════════════════════════════════════════════════════════════════ */
export default function LandingPage() {
  const nav = useNavigate();
  const { isAuthenticated, user, logout } = useAuth();

  const handleOpenConsole = () => {
    if (isAuthenticated) {
      nav('/dashboard');
    } else {
      nav('/sign-in');
    }
  };

  const capabilities = [
    { icon: 'microscope', title: 'Passive Deep Packet Inspection', body: 'Reassembles bi-directional TCP sessions from raw PCAP files. Reconstructs full SMTP, IMAP, and POP3 conversations without decrypting content or violating privacy.' },
    { icon: 'lock', title: 'TLS Handshake & Certificate Analysis', body: 'Parses ClientHello, ServerHello, cipher suites, key exchange parameters, and full X.509 certificate chains with automated chain-of-trust validation.' },
    { icon: 'key', title: 'JA3 / JA4 Cryptographic Fingerprinting', body: 'Computes JA3, JA3S, JA4, and JA4S fingerprints for client and server TLS profile identification and cross-session threat correlation.' },
    { icon: 'clipboard', title: 'Declarative Compliance Engine', body: 'YAML-driven rulebook mapped to NIST SP 800-52r2, PCI-DSS v4.0, RFC 8996, and RFC 8314. Every finding links to the specific standard clause it violates.' },
    { icon: 'brain', title: 'Explainable AI Risk Scoring', body: 'Isolation Forest anomaly detection with SHAP feature attribution. Every risk score is transparent, auditable, and explainable — no black-box decisions.' },
    { icon: 'send', title: 'Attack Simulation Dispatcher', body: 'Interactive test suite: STARTTLS stripping, plaintext credential leakage, legacy TLS negotiation, and hardened TLS 1.3 — all controlled from the web console.' },
  ];

  const standards = [
    { code: 'NIST SP 800-52r2', desc: 'TLS Implementation Guidelines' },
    { code: 'PCI-DSS v4.0', desc: 'Payment Card Data Security' },
    { code: 'RFC 8996', desc: 'Deprecating TLS 1.0 & 1.1' },
    { code: 'RFC 8314', desc: 'Cleartext Considered Obsolete' },
    { code: 'RFC 7525', desc: 'TLS Best Current Practice' },
    { code: 'X.509 v3', desc: 'Certificate Chain Validation' },
  ];

  const pipeline = [
    { icon: 'upload', label: 'Ingest', sub: 'PCAP / Live' },
    { icon: 'search', label: 'Detect', sub: 'Protocol ID' },
    { icon: 'lock', label: 'Parse', sub: 'TLS Handshake' },
    { icon: 'key', label: 'Fingerprint', sub: 'JA3 / JA4' },
    { icon: 'clipboard', label: 'Evaluate', sub: 'Rule Engine' },
    { icon: 'brain', label: 'Score', sub: 'AI + SHAP' },
    { icon: 'chart', label: 'Report', sub: 'PDF / HTML' },
  ];

  return (
    <div className="lp">
      {/* ── Nav ─────────────────────────────────────────────────────────── */}
      <nav className="lp-nav">
        <div className="lp-nav-inner">
          <div className="lp-nav-brand" onClick={() => nav('/')}>
            <Logo size={24} />
            <span className="lp-brandname">Secure SMTP</span>
          </div>
          <div className="lp-nav-right">
            <a href="#capabilities" className="lp-nav-a">Capabilities</a>
            <a href="#architecture" className="lp-nav-a">Architecture</a>
            <a href="#compliance" className="lp-nav-a">Compliance</a>
            {isAuthenticated ? (
              <>
                <button
                  className="lp-btn-signin"
                  onClick={logout}
                  title="Sign out of operator session"
                  style={{ color: 'var(--text-secondary)' }}
                >
                  Sign Out ({user?.name ? user.name.split(' ')[0] : 'Operator'})
                </button>
                <button className="lp-btn-cta" onClick={() => nav('/dashboard')}>
                  Open Console
                  <Icon name="arrowRight" size={14} />
                </button>
              </>
            ) : (
              <>
                <button className="lp-btn-signin" onClick={() => nav('/sign-in')}>
                  Sign In
                </button>
                <button className="lp-btn-cta" onClick={() => nav('/sign-in')}>
                  Sign In to Console
                  <Icon name="lock" size={13} />
                </button>
              </>
            )}
          </div>
        </div>
      </nav>

      {/* ── Hero: Split instrument panel ────────────────────────────────── */}
      <section className="lp-hero">
        <div className="lp-hero-left">
          <h1 className="lp-hero-h1">
            Cryptographic posture intelligence for email infrastructure
          </h1>
          <p className="lp-hero-p">
            Passive network forensics that detects STARTTLS stripping, weak
            ciphers, invalid certificates, and compliance violations across
            SMTP, IMAP, and POP3 — without decrypting a single message.
          </p>
          <div className="lp-hero-actions">
            {isAuthenticated ? (
              <>
                <button className="lp-btn-cta lp-btn-lg" onClick={() => nav('/dashboard')}>
                  <Icon name="terminal" size={16} />
                  Open SOC Console
                </button>
                <button className="lp-btn-outline lp-btn-lg" onClick={logout}>
                  Sign Out
                </button>
              </>
            ) : (
              <>
                <button className="lp-btn-cta lp-btn-lg" onClick={() => nav('/sign-in')}>
                  <Icon name="lock" size={16} />
                  Sign In to Access Console
                </button>
                <button
                  className="lp-btn-outline lp-btn-lg"
                  onClick={() => nav('/sign-up')}
                >
                  Provision Operator
                </button>
              </>
            )}
          </div>
          <div className="lp-hero-proof">
            <div className="lp-proof-item">
              <span className="lp-proof-num">14</span>
              <span className="lp-proof-label">sessions analyzed</span>
            </div>
            <div className="lp-proof-divider" />
            <div className="lp-proof-item">
              <span className="lp-proof-num">7</span>
              <span className="lp-proof-label">findings detected</span>
            </div>
            <div className="lp-proof-divider" />
            <div className="lp-proof-item">
              <span className="lp-proof-num">6</span>
              <span className="lp-proof-label">standards covered</span>
            </div>
          </div>
        </div>
        <div className="lp-hero-right">
          <LiveTerminal />
        </div>
      </section>

      {/* ── Pipeline ────────────────────────────────────────────────────── */}
      <section id="architecture" className="lp-section">
        <h2 className="lp-section-h2">Analysis Pipeline</h2>
        <p className="lp-section-p">Seven-stage pipeline from raw packet capture to actionable intelligence.</p>
        <div className="lp-pipeline">
          {pipeline.map((s, i) => (
            <PipelineStep
              key={i}
              icon={s.icon}
              label={s.label}
              sub={s.sub}
              delay={i * 100}
              active={i === 5}
            />
          ))}
        </div>
      </section>

      {/* ── Capabilities ────────────────────────────────────────────────── */}
      <section id="capabilities" className="lp-section">
        <h2 className="lp-section-h2">Core Capabilities</h2>
        <p className="lp-section-p">
          From passive packet capture to AI-driven risk attribution — the complete cryptographic security lifecycle.
        </p>
        <div className="lp-caps-grid">
          {capabilities.map((c, i) => (
            <Capability key={i} icon={c.icon} title={c.title} body={c.body} idx={i} />
          ))}
        </div>
      </section>

      {/* ── Compliance ──────────────────────────────────────────────────── */}
      <section id="compliance" className="lp-section">
        <h2 className="lp-section-h2">Standards Coverage</h2>
        <p className="lp-section-p">
          Every session evaluated against industry cryptographic security frameworks.
        </p>
        <div className="lp-standards">
          {standards.map((s, i) => (
            <div key={i} className="lp-standard">
              <span className="lp-std-code">{s.code}</span>
              <span className="lp-std-desc">{s.desc}</span>
            </div>
          ))}
        </div>
      </section>

      {/* ── Stack ───────────────────────────────────────────────────────── */}
      <section className="lp-section lp-stack-section">
        <h2 className="lp-section-h2">Technology</h2>
        <div className="lp-stack">
          {['Python', 'FastAPI', 'Scapy', 'scikit-learn', 'SHAP', 'MongoDB', 'React', 'Vite', 'Recharts', 'WebSockets', 'WeasyPrint', 'Uvicorn'].map(t => (
            <span key={t} className="lp-stack-tag">{t}</span>
          ))}
        </div>
      </section>

      {/* ── CTA ─────────────────────────────────────────────────────────── */}
      <section className="lp-bottom-cta">
        <h2>Ready to audit your mail infrastructure?</h2>
        <p>Upload a PCAP. Get instant cryptographic posture intelligence. No agents, no decryption, zero privacy intrusion.</p>
        <div className="lp-hero-actions" style={{ justifyContent: 'center' }}>
          <button className="lp-btn-cta lp-btn-lg" onClick={handleOpenConsole}>
            <Icon name={isAuthenticated ? 'terminal' : 'lock'} size={16} />
            {isAuthenticated ? 'Launch Console' : 'Sign In to Launch Console'}
          </button>
          <a
            href="https://github.com/sharmaharshit1661-web"
            target="_blank"
            rel="noopener noreferrer"
            className="lp-btn-outline lp-btn-lg"
          >
            View Source
          </a>
        </div>
      </section>

      {/* ── Footer ──────────────────────────────────────────────────────── */}
      <footer className="lp-footer">
        <div className="lp-footer-inner">
          <div className="lp-footer-brand">
            <Logo size={18} />
            <span>Secure SMTP</span>
          </div>
          <span className="lp-footer-copy">© {new Date().getFullYear()} Harshit Sharma</span>
          <a
            href="https://github.com/sharmaharshit1661-web"
            target="_blank"
            rel="noopener noreferrer"
            className="lp-footer-link"
          >
            GitHub
          </a>
        </div>
      </footer>
    </div>
  );
}
