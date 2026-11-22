import { getTierFromScore } from './colors.js';

export function riskValue(value) {
  if (value == null || typeof value === 'boolean' || (typeof value === 'string' && !value.trim())) return null;
  const number = Number(value);
  return Number.isFinite(number) ? Math.max(0, Math.min(100, number)) : null;
}

export function sessionTransport(session) {
  const mode = String(session.tls_mode || '').toLowerCase();
  const findings = session.findings || [];
  if (findings.some(({ rule_id }) => ['starttls-stripped', 'no-tls'].includes(rule_id)) || mode === 'none') return 'plaintext';
  if (!['tls', 'starttls', 'implicit_tls', 'implicit'].includes(mode)) return 'unknown';
  const version = String(session.tls_version || '').toLowerCase().replace(/[\s_v]/g, '');
  if (version === 'tls1.3') return 'modern';
  if (version === 'tls1.2') return 'tls12';
  if (['tls1.0', 'tls1.1', 'sslv3', 'ssl3'].includes(version)) return 'legacy';
  return 'unknown';
}

export function summarizeTelemetry(hosts, sessions) {
  const scores = hosts.map(h => riskValue(h.aggregate_risk_score)).filter(v => v !== null);
  const transport = { modern: 0, tls12: 0, legacy: 0, plaintext: 0, unknown: 0 };
  sessions.forEach(session => { transport[sessionTransport(session)] += 1; });
  const confirmedEncrypted = transport.modern + transport.tls12 + transport.legacy;
  return {
    hosts: hosts.length,
    totalSessions: hosts.reduce((sum, host) => sum + Math.max(0, Number(host.session_count) || 0), 0),
    averageRisk: scores.length ? scores.reduce((sum, score) => sum + score, 0) / scores.length : null,
    riskTiers: hosts.reduce((counts, host) => {
      const score = riskValue(host.aggregate_risk_score);
      counts[score == null ? 'unknown' : getTierFromScore(score)] += 1;
      return counts;
    }, { critical: 0, high: 0, medium: 0, clean: 0, unknown: 0 }),
    critical: scores.filter(score => score >= 75).length,
    transport,
    encryptedPercent: sessions.length ? Math.round(confirmedEncrypted / sessions.length * 100) : null,
  };
}

export function filterHosts(hosts, search, tier) {
  const query = search.trim().toLowerCase();
  return hosts.filter(host => {
    const score = riskValue(host.aggregate_risk_score);
    return String(host.ip || '').toLowerCase().includes(query) && (tier === 'ALL' || (score == null ? tier === 'UNKNOWN' : getTierFromScore(score).toUpperCase() === tier));
  });
}

export function validateCapture(file) {
  if (!file || !/\.(pcap|pcapng)$/i.test(file.name || '')) return 'Choose a .pcap or .pcapng capture file.';
  if (!file.size) return 'This capture is empty. Choose a file containing network traffic.';
  if (file.size > 25 * 1024 * 1024) return 'The capture exceeds 25 MB. Split it into a smaller capture before uploading.';
  return '';
}
