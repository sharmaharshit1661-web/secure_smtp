import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import SeverityBadge from '../components/SeverityBadge';
import Icon from '../components/Icon';
import { getComplianceSummary } from '../api/client';

const STANDARDS = [
  {
    id: 'nist',
    name: 'NIST SP 800-52r2',
    title: 'Federal TLS Mandates',
    color: '#3B82F6',
    glow: 'rgba(59, 130, 246, 0.2)',
    rulesCount: 8,
    keyControls: ['TLS 1.2+ Required', 'ECDHE Forward Secrecy', 'RSA ≥ 2048-bit', 'SHA-256+ Signatures'],
    apiFrameworkKey: 'NIST SP 800-52 Rev. 2',
  },
  {
    id: 'pci',
    name: 'PCI-DSS v4.0',
    title: 'Cardholder Data (Req 4.1)',
    color: '#F59E0B',
    glow: 'rgba(245, 158, 11, 0.2)',
    rulesCount: 6,
    keyControls: ['Zero Plaintext', 'Prohibit Early TLS 1.0/1.1', 'Strong AEAD Ciphers', 'Trusted CA Chain'],
    apiFrameworkKey: 'PCI-DSS v4.0 (Req 4.1)',
  },
  {
    id: 'rfc',
    name: 'RFC 8996 & MTA-STS',
    title: 'Modern Transport Security',
    color: '#10B981',
    glow: 'rgba(16, 185, 129, 0.2)',
    rulesCount: 3,
    keyControls: ['TLS 1.0/1.1 Deprecation', 'STARTTLS Downgrade Prevention', 'DANE / MTA-STS Enforced'],
    apiFrameworkKey: 'MTA-STS / DANE',
  },
];

const RULES_DATA = [
  {
    id: 'deprecated-tls-version',
    title: 'Deprecated TLS Protocol Version',
    severity: 'high',
    target: 'handshake.tls_version_negotiated',
    condition: "value in ['SSLv3', 'TLS1.0', 'TLS1.1']",
    message: 'Session negotiated a deprecated protocol version (SSLv3, TLS 1.0, or TLS 1.1).',
    recommendation: 'Disable SSLv3 and TLS 1.0/1.1 on the mail server; mandate TLS 1.2 minimum, prefer TLS 1.3.',
    standards: ['NIST SP 800-52r2', 'RFC 8996'],
  },
  {
    id: 'weak-cipher',
    title: 'Weak or Non-AEAD Cipher Suite',
    severity: 'high',
    target: 'handshake.cipher_suite_negotiated',
    condition: 'is_weak_cipher(value)',
    message: 'Negotiated cipher suite lacks authenticated encryption (AEAD) or uses deprecated algorithms.',
    recommendation: 'Restrict server cipher preferences to AEAD suites (AES-GCM, ChaCha20-Poly1305).',
    standards: ['NIST SP 800-52r2', 'PCI-DSS v4.0'],
  },
  {
    id: 'no-forward-secrecy',
    title: 'Missing Perfect Forward Secrecy (PFS)',
    severity: 'medium',
    target: 'handshake.key_exchange_type',
    condition: "value == 'rsa'",
    message: 'Static RSA key exchange negotiated without ephemeral keys, risking retrospective decryption.',
    recommendation: 'Configure mail server to mandate ephemeral ECDHE or DHE key exchange to preserve PFS.',
    standards: ['NIST SP 800-52r2'],
  },
  {
    id: 'weak-cert-key-rsa',
    title: 'Sub-2048 Bit RSA Certificate Key',
    severity: 'high',
    target: 'certificate.key_length_bits',
    condition: "public_key_algorithm == 'RSA' and value < 2048",
    message: 'Server certificate RSA key modulus is below the mandated 2048-bit baseline.',
    recommendation: 'Reissue certificate with an RSA key length ≥ 2048 bits, or migrate to ECDSA P-256.',
    standards: ['NIST SP 800-52r2', 'PCI-DSS v4.0'],
  },
  {
    id: 'weak-cert-key-ecdsa',
    title: 'Sub-256 Bit ECDSA Certificate Key',
    severity: 'high',
    target: 'certificate.key_length_bits',
    condition: "public_key_algorithm == 'ECDSA' and value < 256",
    message: 'Server certificate ECDSA key curve is below 256 bits, failing cryptographic standards.',
    recommendation: 'Reissue certificate with an ECDSA key on NIST curve P-256 or P-384.',
    standards: ['NIST SP 800-52r2'],
  },
  {
    id: 'weak-cert-signature',
    title: 'Weak Certificate Digest Algorithm',
    severity: 'high',
    target: 'certificate.signature_algorithm',
    condition: "value in ['md5', 'sha1']",
    message: 'Certificate signed using obsolete, collision-vulnerable digest algorithms (MD5 or SHA-1).',
    recommendation: 'Reissue certificate signed with SHA-256 or stronger cryptographic digest.',
    standards: ['NIST SP 800-52r2', 'PCI-DSS v4.0'],
  },
  {
    id: 'cert-expired',
    title: 'Expired X.509 Server Certificate',
    severity: 'critical',
    target: 'certificate.not_after',
    condition: 'is_expired(value)',
    message: 'Server certificate validity window has expired, causing validation aborts.',
    recommendation: 'Renew and deploy a valid X.509 certificate immediately to restore TLS chain validation.',
    standards: ['PCI-DSS v4.0'],
  },
  {
    id: 'cert-expiring-soon',
    title: 'Certificate Approaching Expiration (<30 Days)',
    severity: 'low',
    target: 'certificate.not_after',
    condition: 'is_expiring_soon(value, 30)',
    message: 'Certificate will expire within 30 days, requiring scheduled renewal.',
    recommendation: 'Initiate automated ACME certificate renewal cycle before expiration window.',
    standards: ['Operational Posture'],
  },
  {
    id: 'self-signed-cert',
    title: 'Untrusted Self-Signed Certificate',
    severity: 'medium',
    target: 'certificate.self_signed',
    condition: 'value == true',
    message: 'Server presents a self-signed certificate without a verifiable public or enterprise CA root.',
    recommendation: 'Deploy a certificate signed by a recognized public CA or internal PKI trust anchor.',
    standards: ['PCI-DSS v4.0', 'NIST SP 800-52r2'],
  },
  {
    id: 'starttls-stripped',
    title: 'STARTTLS Stripping Downgrade Detected',
    severity: 'critical',
    target: 'session.starttls_completed',
    condition: "tls_mode == 'starttls' and completed == false and advertised == true",
    message: 'STARTTLS capability was advertised by server but suppressed or stripped before completion.',
    recommendation: 'Investigate for active network adversary on path; enforce MTA-STS and DANE TLSA records.',
    standards: ['RFC 8996', 'NIST SP 800-52r2'],
  },
  {
    id: 'no-tls',
    title: 'Unencrypted Plaintext Transmission',
    severity: 'critical',
    target: 'session.tls_mode',
    condition: "value == 'none'",
    message: 'Complete absence of transport encryption; email credentials and payload transmitted in cleartext.',
    recommendation: 'Enforce mandatory STARTTLS on port 25 or require implicit TLS on port 465.',
    standards: ['NIST SP 800-52r2', 'PCI-DSS v4.0'],
  },
];

export default function RulesCompliance() {
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [standardFilter, setStandardFilter] = useState('ALL');
  const [complianceSummary, setComplianceSummary] = useState(null);
  const [copiedReport, setCopiedReport] = useState(false);

  useEffect(() => {
    getComplianceSummary()
      .then((data) => setComplianceSummary(data))
      .catch(() => {});
  }, []);

  const filteredRules = RULES_DATA.filter((r) => {
    const matchesSearch =
      !search ||
      r.title.toLowerCase().includes(search.toLowerCase()) ||
      r.id.toLowerCase().includes(search.toLowerCase()) ||
      r.message.toLowerCase().includes(search.toLowerCase()) ||
      r.target.toLowerCase().includes(search.toLowerCase()) ||
      r.standards.some((s) => s.toLowerCase().includes(search.toLowerCase()));

    const matchesSev = severityFilter === 'ALL' || r.severity.toLowerCase() === severityFilter.toLowerCase();
    
    const matchesStandard =
      standardFilter === 'ALL' ||
      (standardFilter === 'nist' && r.standards.some((s) => s.includes('NIST'))) ||
      (standardFilter === 'pci' && r.standards.some((s) => s.includes('PCI'))) ||
      (standardFilter === 'rfc' && r.standards.some((s) => s.includes('RFC') || s.includes('MTA-STS')));

    return matchesSearch && matchesSev && matchesStandard;
  });

  const copyAuditSummary = () => {
    const summaryText = {
      evaluated_at: complianceSummary?.evaluated_at || new Date().toISOString(),
      overall_status: complianceSummary?.overall_status || 'EVALUATING',
      overall_score: complianceSummary?.overall_score || 0,
      total_sessions_audited: complianceSummary?.total_sessions_audited || 0,
      framework_scores: complianceSummary?.framework_scores || {},
      enforced_rules_count: RULES_DATA.length,
    };
    navigator.clipboard.writeText(JSON.stringify(summaryText, null, 2)).then(() => {
      setCopiedReport(true);
      setTimeout(() => setCopiedReport(false), 2000);
    });
  };

  const getSeverityBorderColor = (sev) => {
    switch (sev) {
      case 'critical': return 'var(--severity-critical)';
      case 'high': return 'var(--severity-high)';
      case 'medium': return 'var(--severity-medium)';
      case 'low': return 'var(--severity-low)';
      default: return 'var(--border)';
    }
  };

  return (
    <div className="flex flex-col gap-6" style={{ maxWidth: '1440px', margin: '0 auto', paddingBottom: 'var(--space-8)' }}>
      {/* Top Header */}
      <div className="page-header animate-in">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4" style={{ width: '100%' }}>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="page-title" style={{ margin: 0 }}>
                <span className="page-title-icon"><Icon name="clipboard" size={22} /></span>
                Compliance &amp; Security Rules
              </h1>
              <span className="badge badge-accent text-mono" style={{ fontSize: '11px' }}>
                11 POLICIES ACTIVE
              </span>
            </div>
            <p className="page-subtitle">
              Regulatory cryptographic enforcement policies and automated compliance benchmarks.
            </p>
          </div>

          {/* Action Toolbar */}
          <div className="flex items-center gap-3 flex-wrap">
            {complianceSummary && (
              <div
                style={{
                  background: 'var(--bg-surface)',
                  border: `1px solid ${complianceSummary.overall_status === 'COMPLIANT' ? 'var(--sev-clean)' : 'var(--sev-critical)'}`,
                  borderRadius: 'var(--radius-sm)',
                  padding: '6px 14px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '11px',
                }}
              >
                <span
                  className="status-dot"
                  style={{
                    background: complianceSummary.overall_status === 'COMPLIANT' ? 'var(--sev-clean)' : 'var(--sev-critical)',
                    boxShadow: `0 0 8px ${complianceSummary.overall_status === 'COMPLIANT' ? 'rgba(16, 185, 129, 0.4)' : 'rgba(239, 68, 68, 0.4)'}`,
                  }}
                />
                <span style={{ color: 'var(--text-muted)' }}>FLEET AUDIT:</span>
                <span
                  style={{
                    color: complianceSummary.overall_status === 'COMPLIANT' ? 'var(--sev-clean)' : 'var(--sev-critical)',
                    fontWeight: 700,
                  }}
                >
                  {complianceSummary.overall_score}% [{complianceSummary.overall_status.replace('_', ' ')}]
                </span>
              </div>
            )}

            <button
              className="btn btn-outline"
              style={{ fontSize: '11px', padding: '6px 14px', textTransform: 'uppercase', gap: '6px' }}
              onClick={copyAuditSummary}
            >
              <Icon name={copiedReport ? 'check' : 'copy'} size={12} />
              {copiedReport ? 'Copied JSON' : 'Export Audit'}
            </button>

            <Link
              to="/dashboard/sessions"
              className="btn btn-outline"
              style={{ fontSize: '11px', padding: '6px 14px', textTransform: 'uppercase', gap: '6px' }}
            >
              <Icon name="search" size={12} />
              Inspect Sessions
            </Link>
          </div>
        </div>
      </div>

      {/* Compliance Framework Benchmark Cards */}
      <div className="grid grid-1 md:grid-3 gap-4">
        {STANDARDS.map((std, i) => {
          const frameworkScore = complianceSummary?.framework_scores?.[std.apiFrameworkKey];
          const scoreDisplay = frameworkScore !== undefined ? `${frameworkScore.toFixed(1)}%` : null;

          return (
            <div
              key={std.id}
              className="compliance-framework-card animate-in"
              style={{
                '--framework-color': std.color,
                animationDelay: `${i * 60}ms`,
              }}
            >
              <div>
                <div className="flex justify-between items-center" style={{ marginBottom: '8px' }}>
                  <div className="flex items-center gap-2">
                    <span style={{ color: std.color }}><Icon name="shield" size={15} /></span>
                    <span className="font-bold text-sm" style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
                      {std.name}
                    </span>
                  </div>
                  <span className="badge text-mono" style={{ fontSize: '10px', borderColor: 'var(--border)' }}>
                    {std.rulesCount} Rules
                  </span>
                </div>

                <div className="text-xs text-secondary font-medium" style={{ marginBottom: '12px' }}>
                  {std.title}
                </div>

                {/* Score Progress Meter */}
                {scoreDisplay !== null ? (
                  <div style={{ marginBottom: '14px' }}>
                    <div className="flex justify-between items-center text-xs text-mono" style={{ marginBottom: '6px' }}>
                      <span className="text-muted" style={{ fontSize: '11px' }}>Fleet Compliance</span>
                      <span style={{ color: std.color, fontWeight: 700, fontSize: '12px' }}>{scoreDisplay}</span>
                    </div>
                    <div className="compliance-progress-track">
                      <div
                        className="compliance-progress-fill"
                        style={{ width: `${Math.max(frameworkScore, 3)}%` }}
                      />
                    </div>
                  </div>
                ) : (
                  <div className="text-xs text-muted" style={{ marginBottom: '14px', fontFamily: 'var(--font-mono)' }}>
                    Automated Inspection Active
                  </div>
                )}

                {/* Key Controls Chips */}
                <div className="flex flex-wrap gap-1">
                  {std.keyControls.map((ctrl, idx) => (
                    <span
                      key={idx}
                      className="badge text-mono"
                      style={{
                        fontSize: '10px',
                        padding: '2px 8px',
                        background: 'var(--bg-inset)',
                        color: 'var(--text-secondary)',
                      }}
                    >
                      {ctrl}
                    </span>
                  ))}
                </div>
              </div>

              <div className="flex justify-between items-center pt-2" style={{ borderTop: '1px solid var(--border)' }}>
                <button
                  type="button"
                  className="btn btn-outline btn-xs"
                  onClick={() => setStandardFilter(standardFilter === std.id ? 'ALL' : std.id)}
                  style={{
                    fontSize: '10px',
                    borderColor: standardFilter === std.id ? std.color : 'var(--border)',
                    color: standardFilter === std.id ? std.color : 'var(--text-secondary)',
                  }}
                >
                  {standardFilter === std.id ? 'Showing Rules ✓' : 'Filter by Standard →'}
                </button>
                <span className="text-xs text-muted text-mono" style={{ fontSize: '10px' }}>
                  Deterministic
                </span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Active Violations Highlight Strip (if non-compliant) */}
      {complianceSummary?.top_violations && complianceSummary.top_violations.length > 0 && (
        <div
          className="card animate-in"
          style={{
            padding: '14px 18px',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            background: 'rgba(239, 68, 68, 0.03)',
          }}
        >
          <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-3">
            <div className="flex items-center gap-2">
              <span style={{ color: 'var(--sev-critical)' }}><Icon name="alert" size={16} /></span>
              <span className="font-bold text-xs text-mono" style={{ color: 'var(--sev-critical)', textTransform: 'uppercase' }}>
                Active Fleet Non-Compliance ({complianceSummary.total_sessions_audited} Sessions Evaluated)
              </span>
            </div>

            <div className="flex gap-2 flex-wrap items-center">
              {complianceSummary.top_violations.slice(0, 3).map((v, idx) => (
                <span
                  key={idx}
                  className="badge badge-critical text-mono"
                  style={{ fontSize: '10px', padding: '3px 8px' }}
                >
                  {v.frequency}x {v.violation.split(':')[0].replace(/\[.*?\]\s*/, '')}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Rules Matrix Browser */}
      <div className="card" style={{ padding: '20px' }}>
        {/* Controls Toolbar */}
        <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-4" style={{ marginBottom: '18px' }}>
          <div className="flex items-center gap-2">
            <Icon name="shield" size={16} />
            <span className="font-bold text-sm" style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Cryptographic Policies Catalog ({filteredRules.length})
            </span>
          </div>

          <div className="flex gap-2 flex-wrap items-center" style={{ width: '100%', maxWidth: '780px' }}>
            {/* Standard Filter Pills */}
            <div className="flex gap-1 flex-wrap">
              <button
                type="button"
                className={`compliance-filter-btn ${standardFilter === 'ALL' ? 'active' : ''}`}
                onClick={() => setStandardFilter('ALL')}
              >
                All Standards
              </button>
              <button
                type="button"
                className={`compliance-filter-btn ${standardFilter === 'nist' ? 'active' : ''}`}
                onClick={() => setStandardFilter('nist')}
              >
                NIST SP 800-52r2
              </button>
              <button
                type="button"
                className={`compliance-filter-btn ${standardFilter === 'pci' ? 'active' : ''}`}
                onClick={() => setStandardFilter('pci')}
              >
                PCI-DSS v4.0
              </button>
              <button
                type="button"
                className={`compliance-filter-btn ${standardFilter === 'rfc' ? 'active' : ''}`}
                onClick={() => setStandardFilter('rfc')}
              >
                RFC 8996
              </button>
            </div>

            {/* Search Input */}
            <div style={{ flex: 1, minWidth: '180px' }}>
              <input
                type="text"
                className="input text-xs"
                placeholder="Search rule title, target, or standard..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                style={{ width: '100%', padding: '5px 10px' }}
              />
            </div>

            {/* Severity Filter */}
            <select
              className="select text-xs"
              style={{ width: '140px', padding: '5px 8px' }}
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
            >
              <option value="ALL">All Severities</option>
              <option value="critical">Critical (3)</option>
              <option value="high">High (5)</option>
              <option value="medium">Medium (2)</option>
              <option value="low">Low (1)</option>
            </select>
          </div>
        </div>

        {/* Rules Cards List */}
        <div className="flex flex-col gap-3">
          {filteredRules.map((rule) => {
            const sevColor = getSeverityBorderColor(rule.severity);

            return (
              <div
                key={rule.id}
                className="compliance-rule-card"
                style={{
                  '--rule-severity-color': sevColor,
                }}
              >
                {/* Rule Header */}
                <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-2">
                  <div className="flex items-center gap-3 flex-wrap">
                    <SeverityBadge severity={rule.severity} />
                    <span className="font-bold text-xs" style={{ color: 'var(--text-primary)', fontSize: '13px' }}>
                      {rule.title}
                    </span>
                    <span
                      className="badge text-mono"
                      style={{
                        fontSize: '11px',
                        background: 'var(--bg-inset)',
                        color: 'var(--text-secondary)',
                      }}
                    >
                      {rule.id}
                    </span>
                  </div>

                  {/* Standards Badges */}
                  <div className="flex gap-1 flex-wrap">
                    {rule.standards.map((s, i) => (
                      <span
                        key={i}
                        className="badge text-mono"
                        style={{
                          fontSize: '10px',
                          padding: '2px 8px',
                          background: 'rgba(255, 255, 255, 0.03)',
                          borderColor: 'var(--border)',
                          color: 'var(--text-secondary)',
                        }}
                      >
                        {s}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Target & Condition Line */}
                <div className="flex items-center gap-2 flex-wrap text-xs text-mono" style={{ fontSize: '11px' }}>
                  <span className="text-muted">Target:</span>
                  <span
                    style={{
                      background: 'var(--bg-inset)',
                      padding: '2px 8px',
                      borderRadius: 'var(--radius-xs)',
                      border: '1px solid var(--border)',
                      color: 'var(--accent)',
                    }}
                  >
                    {rule.target}
                  </span>

                  <span className="text-muted" style={{ marginLeft: '6px' }}>Condition:</span>
                  <span
                    style={{
                      background: '#040404',
                      padding: '2px 8px',
                      borderRadius: 'var(--radius-xs)',
                      border: '1px solid var(--border)',
                      color: 'var(--text-primary)',
                    }}
                  >
                    {rule.condition}
                  </span>
                </div>

                {/* Violation Message */}
                <div className="text-xs text-secondary" style={{ lineHeight: '1.5' }}>
                  {rule.message}
                </div>

                {/* Remediation Directive */}
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '8px',
                    padding: '8px 12px',
                    background: 'rgba(255, 255, 255, 0.015)',
                    border: '1px solid var(--border)',
                    borderRadius: 'var(--radius-xs)',
                    fontSize: '11px',
                  }}
                >
                  <span style={{ color: 'var(--accent)', flexShrink: 0, marginTop: '1px' }}>
                    <Icon name="check" size={13} />
                  </span>
                  <div style={{ color: 'var(--text-secondary)', lineHeight: '1.4' }}>
                    <strong style={{ color: 'var(--text-primary)', marginRight: '6px' }}>Remediation:</strong>
                    {rule.recommendation}
                  </div>
                </div>
              </div>
            );
          })}

          {filteredRules.length === 0 && (
            <div className="empty-state" style={{ padding: '40px 20px' }}>
              <div className="empty-state-icon"><Icon name="search" size={24} /></div>
              <p className="text-mono text-xs text-muted" style={{ marginTop: '8px' }}>
                No compliance rules match the specified search or filter criteria.
              </p>
              <button
                type="button"
                className="btn btn-outline btn-sm"
                onClick={() => {
                  setSearch('');
                  setSeverityFilter('ALL');
                  setStandardFilter('ALL');
                }}
                style={{ marginTop: '12px' }}
              >
                Reset Filters
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
