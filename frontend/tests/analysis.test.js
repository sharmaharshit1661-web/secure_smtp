import test from 'node:test';
import assert from 'node:assert/strict';
import { waitForAnalysis } from '../src/utils/analysis.js';

test('upload polling resolves only after analysis finishes', async () => {
  const jobs = [{ status: 'queued' }, { status: 'running' }, { status: 'done', sessions: 4 }];
  const observed = [];
  let pauses = 0;
  const result = await waitForAnalysis('capture-1', {
    getStatus: async id => { assert.equal(id, 'capture-1'); return jobs.shift(); },
    onStatus: value => observed.push(value), delay: async () => { pauses++; },
  });
  assert.equal(result.sessions, 4);
  assert.deepEqual(observed, ['queued', 'running', 'done']);
  assert.equal(pauses, 2);
});
test('analysis failure reports the server reason without retrying', async () => {
  await assert.rejects(waitForAnalysis('bad-capture', { getStatus: async () => ({ status: 'failed', error_message: 'Unreadable capture' }), delay: () => assert.fail('must not wait') }), /Unreadable capture/);
});
test('network errors remain failures rather than success or infinite retries', async () => {
  await assert.rejects(waitForAnalysis('offline', { getStatus: async () => { throw new Error('API unavailable'); } }), /API unavailable/);
});
test('polling has a finite limit and leaves the job recoverable', async () => {
  let calls = 0;
  let pauses = 0;
  await assert.rejects(waitForAnalysis('slow', { getStatus: async () => { calls++; return { status: 'running' }; }, attempts: 3, delay: async () => { pauses++; } }), /still running/);
  assert.equal(calls, 3);
  assert.equal(pauses, 2);
});
test('an aborted request never updates status or reports completion', async () => {
  const controller = new AbortController();
  await assert.rejects(waitForAnalysis('cancelled', { signal: controller.signal, getStatus: async () => { controller.abort(); return { status: 'done' }; }, onStatus: () => assert.fail('stale update') }), { name: 'AbortError' });
});
test('a previously aborted analysis never sends a request', async () => {
  const controller = new AbortController(); controller.abort();
  await assert.rejects(waitForAnalysis('cancelled', { signal: controller.signal, getStatus: () => assert.fail('stale request') }), { name: 'AbortError' });
});
