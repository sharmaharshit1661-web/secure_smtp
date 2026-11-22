import test from 'node:test';
import assert from 'node:assert/strict';
import { errorMessage, fetchWithDeadline } from '../src/api/transport.js';

test('validation errors name their fields instead of rendering object strings', () => {
  assert.equal(errorMessage([{loc:['body','name'], msg:'Field required'}], 422), 'name: Field required');
  assert.match(errorMessage({}, 503), /unavailable/);
  assert.match(errorMessage(null, 401), /Sign in/);
  assert.equal(errorMessage('Capture is corrupt', 400), 'Capture is corrupt');
});

test('stalled requests abort and report a recoverable timeout', async () => {
  const previous = globalThis.fetch;
  let aborted = false;
  globalThis.fetch = (url, {signal}) => new Promise((resolve, reject) => {
    signal.addEventListener('abort', () => { aborted = true; reject(new DOMException('Aborted', 'AbortError')); });
  });
  try {
    await assert.rejects(fetchWithDeadline('/api/test', {}, 5), /timed out/);
    assert.ok(aborted);
  } finally { globalThis.fetch = previous; }
});

test('caller cancellation stays cancellation instead of a connection error', async () => {
  const previous = globalThis.fetch;
  const controller = new AbortController();
  globalThis.fetch = (url, {signal}) => new Promise((resolve, reject) => {
    signal.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')));
  });
  try {
    const pending = fetchWithDeadline('/api/test', {signal: controller.signal});
    controller.abort();
    await assert.rejects(pending, {name:'AbortError'});
  } finally { globalThis.fetch = previous; }
});
