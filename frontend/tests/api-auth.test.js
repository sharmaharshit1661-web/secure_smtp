import test from 'node:test';
import assert from 'node:assert/strict';
import { configureTokenProvider, getHosts, uploadPcap } from '../src/api/client.js';

test('API requests require sign-in and never use a fallback credential', async () => {
  const original = globalThis.fetch;
  let called = false;
  globalThis.fetch = async () => { called = true; };
  configureTokenProvider(null);
  try {
    await assert.rejects(getHosts(), /Sign in/);
    assert.equal(called, false);
  } finally { globalThis.fetch = original; }
});

test('each API request obtains a current token rather than saving a shared key', async () => {
  const original = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, options) => {
    calls.push({ url, headers: options.headers });
    return { ok: true, json: async () => [] };
  };
  let version = 0;
  configureTokenProvider(async () => `current-token-${++version}`);
  try {
    await getHosts();
    await getHosts();
    assert.equal(calls[0].headers.Authorization, 'Bearer current-token-1');
    assert.equal(calls[1].headers.Authorization, 'Bearer current-token-2');
    assert.equal(calls[0].headers['X-API-Key'], undefined);
    assert.ok(calls.every(call => !call.url.includes('token') && !call.url.includes('api_key')));
  } finally { globalThis.fetch = original; configureTokenProvider(null); }
});

test('capture upload uses the same verified identity and preserves multipart boundaries', async () => {
  const original = globalThis.fetch;
  configureTokenProvider(async () => 'session-token');
  globalThis.fetch = async (url, options) => {
    assert.equal(url, '/api/analyze');
    assert.equal(options.headers.Authorization, 'Bearer session-token');
    assert.equal(options.headers['Content-Type'], undefined);
    assert.ok(options.body instanceof FormData);
    return { ok: true, json: async () => ({ job_id: 'example' }) };
  };
  try { assert.equal((await uploadPcap(new Blob(['capture']))).job_id, 'example'); }
  finally { globalThis.fetch = original; configureTokenProvider(null); }
});
