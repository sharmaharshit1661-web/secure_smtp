import test from 'node:test';
import assert from 'node:assert/strict';
import { riskValue, sessionTransport, summarizeTelemetry, filterHosts, validateCapture } from '../src/utils/telemetry.js';

test('missing risk remains unknown while a real zero remains valid', () => {
  for (const value of [null, undefined, '', ' ', false, 'invalid', Infinity, NaN]) assert.equal(riskValue(value), null);
  assert.equal(riskValue(0), 0);
  assert.equal(riskValue('75'), 75);
  assert.equal(riskValue(120), 100);
  assert.equal(riskValue(-5), 0);
});
test('transport classification requires observed protocol evidence', () => {
  assert.equal(sessionTransport({}), 'unknown');
  assert.equal(sessionTransport({ tls_mode: 'starttls' }), 'unknown');
  assert.equal(sessionTransport({ tls_mode: 'starttls', tls_version: 'TLSv1.3' }), 'modern');
  assert.equal(sessionTransport({ tls_mode: 'implicit_tls', tls_version: 'TLS 1.2' }), 'tls12');
  assert.equal(sessionTransport({ tls_mode: 'implicit', tls_version: 'TLS 1.3' }), 'modern');
  assert.equal(sessionTransport({ tls_mode: 'tls', tls_version: 'TLSv1.0' }), 'legacy');
  assert.equal(sessionTransport({ tls_mode: 'none' }), 'plaintext');
  assert.equal(sessionTransport({ tls_mode: 'starttls', tls_version: 'TLS 1.3', findings: [{ rule_id: 'starttls-stripped' }] }), 'plaintext');
});
test('empty telemetry has no invented healthy percentage or average', () => {
  const summary = summarizeTelemetry([], []);
  assert.equal(summary.averageRisk, null);
  assert.equal(summary.encryptedPercent, null);
  assert.equal(summary.totalSessions, 0);
});
test('unknown observations remain in the transport denominator, not the risk average', () => {
  const summary = summarizeTelemetry([{ aggregate_risk_score: 80, session_count: 2 }, { aggregate_risk_score: null, session_count: 3 }, { aggregate_risk_score: 0, session_count: 1 }], [{ tls_mode: 'tls', tls_version: 'TLS1.3' }, { tls_mode: 'none' }, {}]);
  assert.equal(summary.averageRisk, 40);
  assert.equal(summary.critical, 1);
  assert.equal(summary.totalSessions, 6);
  assert.equal(summary.encryptedPercent, 33);
  assert.deepEqual(summary.transport, { modern: 1, tls12: 0, legacy: 0, plaintext: 1, unknown: 1 });
});
test('host filters combine a trimmed search and a valid scored tier', () => {
  const hosts = [{ ip: 'Mail.Example', aggregate_risk_score: 80 }, { ip: 'other', aggregate_risk_score: 30 }, { ip: 'mail.unknown', aggregate_risk_score: null }];
  assert.equal(filterHosts(hosts, ' MAIL ', 'ALL').length, 2);
  assert.deepEqual(filterHosts(hosts, ' MAIL ', 'CRITICAL'), [hosts[0]]);
  assert.deepEqual(filterHosts(hosts, '', 'CLEAN'), []);
});
test('capture selection rejects empty, unsupported, and oversized files', () => {
  assert.equal(validateCapture({ name: 'traffic.PCAPNG', size: 25 * 1024 * 1024 }), '');
  assert.ok(validateCapture({ name: 'traffic.pcap', size: 0 }));
  assert.ok(validateCapture({ name: 'traffic.exe', size: 100 }));
  assert.ok(validateCapture({ name: 'traffic.pcap', size: 25 * 1024 * 1024 + 1 }));
  assert.ok(validateCapture(null));
});

test('donut counts every host once, including unknown scores and tier boundaries', () => {
  const hosts = [0, 24.9, 25, 49.9, 50, 74.9, 75, 100, null].map((score, index) => ({ ip: `host-${index}`, aggregate_risk_score: score }));
  const { riskTiers } = summarizeTelemetry(hosts, []);
  assert.deepEqual(riskTiers, { critical: 2, high: 2, medium: 2, clean: 2, unknown: 1 });
  assert.equal(Object.values(riskTiers).reduce((sum, count) => sum + count, 0), hosts.length);
  for (const [tier, count] of Object.entries(riskTiers)) assert.equal(filterHosts(hosts, '', tier.toUpperCase()).length, count);
});
test('unknown risk selection does not include low-risk hosts', () => {
  const hosts = [{ ip: 'mail-unknown', aggregate_risk_score: null }, { ip: 'mail-zero', aggregate_risk_score: 0 }];
  assert.deepEqual(filterHosts(hosts, 'mail', 'UNKNOWN'), [hosts[0]]);
  assert.deepEqual(filterHosts(hosts, '', 'ALL'), hosts);
});
