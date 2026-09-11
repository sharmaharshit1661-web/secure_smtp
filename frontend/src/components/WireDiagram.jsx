import SeverityBadge from './SeverityBadge';

export default function WireDiagram({ session }) {
  const isStarttls = String(session.tls_mode).toLowerCase() === 'starttls';
  const isStripped = isStarttls && !session.starttls_completed;
  const proto = String(session.protocol).toUpperCase();
  const tlsMode = String(session.tls_mode).toUpperCase();

  let tlsBadge;
  if (isStripped) {
    tlsBadge = <SeverityBadge severity="critical" />;
  } else if (session.tls_mode !== 'none') {
    tlsBadge = <SeverityBadge severity="clean" />;
  } else {
    tlsBadge = <SeverityBadge severity="critical" />;
  }

  let statusLabel;
  if (isStripped) statusLabel = 'STARTTLS Stripped';
  else if (session.tls_mode !== 'none') statusLabel = `${tlsMode} TLS`;
  else statusLabel = 'Plaintext';

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
          <span style={{ color: isStripped ? 'var(--sev-critical)' : 'var(--accent)' }}>{statusLabel}</span>
        </div>
        <div className="wire-line" />
        <div className="wire-pcap">Source: {session.pcap_source || 'Live Feed'}</div>
      </div>
      <div className="wire-endpoint">
        <div className="wire-endpoint-label">Destination Server</div>
        <div className="wire-endpoint-addr">{session.dst_ip}:{session.dst_port}</div>
      </div>
    </div>
  );
}
