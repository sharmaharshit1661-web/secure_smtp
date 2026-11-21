import { useState } from 'react';
import Icon from './Icon';
import { formatDate } from '../utils/format';

export default function CertChain({ certificates = [] }) {
  if (!certificates.length) {
    return (
      <div className="empty-state">
        <div className="empty-state-icon"><Icon name="certificate" size={24} /></div>
        <p>No X.509 certificates exchanged (plaintext or TLS 1.3 encrypted handshake).</p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-2">
      {certificates.map((cert, i) => (
        <CertNode key={i} cert={cert} defaultOpen={i === 0} />
      ))}
    </div>
  );
}

function CertNode({ cert, defaultOpen }) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <div className="expander">
      <button className="expander-trigger" onClick={() => setOpen(!open)}>
        <span style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
          <Icon name="certificate" size={15} style={{ color: 'var(--accent)' }} />
          Certificate [{cert.chain_position}] — {cert.subject?.slice(0, 50)}
        </span>
        <span className={`expander-chevron ${open ? 'open' : ''}`}>
          <Icon name="chevron" size={14} />
        </span>
      </button>
      {open && (
        <div className="expander-content">
          <div className="info-grid">
            <div>
              <div className="info-item-label">Subject</div>
              <div className="info-item-value">{cert.subject}</div>
            </div>
            <div>
              <div className="info-item-label">Issuer</div>
              <div className="info-item-value">{cert.issuer}</div>
            </div>
            <div>
              <div className="info-item-label">Valid From</div>
              <div className="info-item-value">{formatDate(cert.not_before)}</div>
            </div>
            <div>
              <div className="info-item-label">Valid Until</div>
              <div className="info-item-value">{formatDate(cert.not_after)}</div>
            </div>
            <div>
              <div className="info-item-label">Public Key</div>
              <div className="info-item-value">{cert.public_key_algorithm} ({cert.key_length_bits} bits)</div>
            </div>
            <div>
              <div className="info-item-label">Signature Algorithm</div>
              <div className="info-item-value">{cert.signature_algorithm}</div>
            </div>
            <div>
              <div className="info-item-label">Self-Signed</div>
              <div className="info-item-value">
                {cert.self_signed
                  ? <span className="text-critical font-semibold">Self-signed — untrusted</span>
                  : <span className="text-clean font-semibold">Issuer declared</span>}
              </div>
            </div>
            <div>
              <div className="info-item-label">Observed chain checks</div>
              <div className="info-item-value">
                {cert.chain_valid
                  ? <span className="text-clean font-semibold">No failure observed; trust not verified</span>
                  : <span className="text-critical font-semibold">Invalid</span>}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
