import Notice from '../components/Notice';
import useClipboard from '../hooks/useClipboard';
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
    color: 'var(--sev-medium)',
    glow: 'rgba(245, 158, 11, 0.2)',
    rulesCount: 6,
    keyControls: ['Zero Plaintext', 'Prohibit Early TLS 1.0/1.1', 'Strong AEAD Ciphers', 'Trusted CA Chain'],
    apiFrameworkKey: 'PCI-DSS v4.0 (Req 4.1)',
  },
  {
    id: 'rfc',
    name: 'RFC 8996 & MTA-STS',
    title: 'Modern Transport Security',
    color: 'var(--accent)',
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
  const { copyText, clipboardError } = useClipboard();
  const [error, setError] = useState('');
  const [retryKey, setRetryKey] = useState(0);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [standardFilter, setStandardFilter] = useState('ALL');
  const [complianceSummary, setComplianceSummary] = useState(null);
  const [copiedReport, setCopiedReport] = useState(false);

  useEffect(() => {
    setError('');
    getComplianceSummary()
      .then((data) => setComplianceSummary(data))
      .catch(err => setError(`Could not load compliance results. ${err.message}`));
  }, [retryKey]);

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
    copyText(JSON.stringify(summaryText, null, 2), () => {
      setCopiedReport(true);
      setTimeout(() => setCopiedReport(false), 2000);
    });
  };

  return <div className="simple-page">
    <header className="simple-heading"><div><h1>Compliance</h1><p>Check your results and explore the rules behind them.</p></div><button className="btn btn-outline" disabled={!complianceSummary} onClick={copyAuditSummary}>{copiedReport ? 'Copied' : 'Copy audit JSON'}</button></header>
    {clipboardError && <Notice>{clipboardError}</Notice>}
    {error && <Notice onRetry={() => setRetryKey(key => key + 1)}>{error}</Notice>}
    <section className="standards-overview" aria-label="Compliance by standard">{STANDARDS.map(standard => {
      const score = complianceSummary?.framework_scores?.[standard.apiFrameworkKey];
      return <button key={standard.id} className="standard-summary" aria-pressed={standardFilter === standard.id} onClick={() => setStandardFilter(standardFilter === standard.id ? 'ALL' : standard.id)}><span>{standard.name}</span><strong>{Number.isFinite(score) ? `${score.toFixed(1)}%` : '—'}</strong><small>{standardFilter === standard.id ? 'Showing matching rules' : 'View rules'}</small></button>;
    })}</section>
    {!!complianceSummary?.top_violations?.length && <details className="simple-details"><summary>Top violations <span>{complianceSummary.total_sessions_audited} sessions assessed</span></summary><div className="simple-stack"><dl className="simple-definition-list">{complianceSummary.top_violations.slice(0, 3).map((item, index) => <div key={index}><dt>{item.violation}</dt><dd>{item.frequency}×</dd></div>)}</dl><Link className="text-action" to="/dashboard/sessions">Inspect sessions →</Link></div></details>}
    <section className="simple-stack">
      <div className="simple-row"><h2>Security rules <span className="ui-count">{filteredRules.length}</span></h2>{standardFilter !== 'ALL' && <button className="text-action" onClick={() => setStandardFilter('ALL')}>Clear standard filter</button>}</div>
      <div className="simple-rule-filters"><label className="simple-field" htmlFor="rule-search"><span>Search</span><input id="rule-search" type="search" className="input" value={search} onChange={event => setSearch(event.target.value)} placeholder="Rule, standard, or keyword" /></label><label className="simple-field" htmlFor="rule-severity"><span>Severity</span><select id="rule-severity" className="select" value={severityFilter} onChange={event => setSeverityFilter(event.target.value)}>{['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(value => <option key={value} value={value}>{value === 'ALL' ? 'All severities' : value[0] + value.slice(1).toLowerCase()}</option>)}</select></label></div>
      <div className="rule-list">{filteredRules.map(rule => <details className="rule-disclosure" key={rule.id}><summary><SeverityBadge severity={rule.severity} /><strong>{rule.title}</strong><span className="rule-id">{rule.id}</span><Icon name="chevron" size={15} /></summary><div className="rule-detail"><p>{rule.message}</p><p><strong>Recommended action</strong><br />{rule.recommendation}</p><dl className="simple-definition-list"><div><dt>Rule</dt><dd>{rule.id}</dd></div><div><dt>Applies to</dt><dd>{rule.target}</dd></div><div><dt>Condition</dt><dd>{rule.condition}</dd></div><div><dt>Standards</dt><dd>{rule.standards.join(' · ')}</dd></div></dl></div></details>)}</div>
      {!filteredRules.length && <div className="simple-empty"><p>No matching rules.</p><button className="btn btn-outline" onClick={() => { setSearch(''); setSeverityFilter('ALL'); setStandardFilter('ALL'); }}>Reset filters</button></div>}
    </section>
  </div>;
}
