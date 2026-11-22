import SeverityBadge from './SeverityBadge';

export default function WireDiagram({ session }) {
  const mode = String(session.tls_mode || '').toLowerCase();
  const stripped = (session.findings || []).some(finding => finding.rule_id === 'starttls-stripped');
  const incomplete = mode === 'starttls' && session.starttls_completed === false;
  const encrypted = ['tls', 'implicit_tls'].includes(mode) || (mode === 'starttls' && session.starttls_completed === true);
  const proto = String(session.protocol || 'Unknown protocol').toUpperCase();
  const statusLabel = stripped ? 'STARTTLS stripping detected' : incomplete ? 'STARTTLS incomplete' : encrypted ? (mode === 'starttls' ? 'STARTTLS completed' : 'TLS connection') : mode === 'none' ? 'Plaintext' : 'Transport unknown';
  const tlsBadge = <SeverityBadge severity={stripped ? 'critical' : incomplete || mode === 'none' ? 'high' : 'info'} />;

  return (
    <div className="wire-diagram">
      <div className="wire-endpoint">
        <div className="wire-endpoint-label">Source Client</div>
        <div className="wire-endpoint-addr">{session.src_ip}:{session.src_port}</div>
      </div>
      <div className="wire-connection">
        <div className="wire-protocol">
          <span>{proto}</span>
          {tlsBadge}
          <span style={{ color: stripped ? 'var(--sev-critical)' : 'var(--text-secondary)' }}>{statusLabel}</span>
        </div>
        <div className="wire-line" />
        <div className="wire-pcap">Source: {session.pcap_source || 'Not recorded'}</div>
      </div>
      <div className="wire-endpoint">
        <div className="wire-endpoint-label">Destination Server</div>
        <div className="wire-endpoint-addr">{session.dst_ip}:{session.dst_port}</div>
      </div>
    </div>
  );
}
