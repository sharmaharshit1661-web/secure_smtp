/**
 * Fetch wrapper for the Secure SMTP FastAPI backend.
 */

// Default to empty string so local Vite dev proxy (/api -> :8000) is leveraged seamlessly without CORS hurdles,
// while still supporting explicit VITE_API_BASE or VITE_API_URL for cross-origin deployments (e.g. Vercel -> Render).
const rawBase = import.meta.env.VITE_API_BASE || import.meta.env.VITE_API_URL || '';
export const API_BASE = rawBase.replace(/\/+$/, '');
let tokenProvider = null;
export function setTokenProvider(provider) { tokenProvider = provider; }
async function authHeaders() {
  const token = tokenProvider ? await tokenProvider() : null;
  return token ? { Authorization: `Bearer ${token}` } : {};
}
export async function authRequest(path, body) {
  return request(`/api/auth${path}`, body === undefined ? {} : {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
}
export async function getLiveWebSocketUrl() {
  const { ticket } = await authRequest('/ws-ticket', {});
  const base = API_BASE || window.location.origin;
  return `${base.replace(/^http/, 'ws')}/ws/live?token=${encodeURIComponent(ticket)}`;
}

async function request(path, options = {}) {
  const url = `${API_BASE}${path}`;
  const res = await fetch(url, {
    ...options,
    credentials: 'include',
    headers: {
      ...await authHeaders(),
      ...options.headers,
    },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || `API error: ${res.status}`);
  }
  return res.json();
}

export async function getHosts() {
  return request('/api/hosts');
}

export async function getHostDetail(hostId) {
  return request(`/api/hosts/${hostId}`);
}

export async function getSessionDetail(sessionId) {
  return request(`/api/sessions/${sessionId}`);
}

export async function getSessionExplanation(sessionId) {
  return request(`/api/sessions/${sessionId}/explain`);
}

export async function getAnalysisStatus(jobId) {
  return request(`/api/analyze/${jobId}/status`);
}

export async function uploadPcap(file) {
  const formData = new FormData();
  formData.append('file', file);
  const url = `${API_BASE}/api/analyze`;
  const res = await fetch(url, {
    method: 'POST',
    credentials: 'include',
    body: formData,
    headers: {
      ...await authHeaders(),
    },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || `Upload failed: ${res.status}`);
  }
  return res.json();
}

export async function downloadReport(jobId, format) {
  const res = await fetch(`${API_BASE}/api/reports/${encodeURIComponent(jobId)}.${format}`, {
    credentials: 'include', headers: await authHeaders(),
  });
  if (!res.ok) throw new Error('Unable to download report. Check your session and assessment.');
  const url = URL.createObjectURL(await res.blob());
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `secure_smtp_report_${jobId}.${format}`;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export async function getCopilotRemediation(sessionId, serverType = 'postfix') {
  return request(`/api/sessions/${sessionId}/copilot/remediate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ server_type: serverType }),
  });
}

export async function getCopilotBriefing(sessionId) {
  return request(`/api/sessions/${sessionId}/copilot/briefing`, {
    method: 'POST',
  });
}

export async function askCopilot(sessionId, query) {
  return request(`/api/sessions/${sessionId}/copilot/ask`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query }),
  });
}

export async function getLiveStatus() {
  return request('/api/live/status');
}

export async function startLiveLab() {
  return request('/api/live/start-lab', { method: 'POST' });
}

export async function stopLiveLab() {
  return request('/api/live/stop-lab', { method: 'POST' });
}

export async function simulateLiveScenario(scenario) {
  return request(`/api/live/simulate/${scenario}`, { method: 'POST' });
}

export async function clearLiveHistory() {
  return request('/api/live/clear-history', { method: 'POST' });
}

export async function dispatchCustomMail(payload) {
  return request('/api/live/dispatch-custom', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

export async function getAiOverview() {
  return request('/api/ai/overview');
}

export async function askGlobalCopilot(query, sessionId = null) {
  return request('/api/ai/copilot/ask', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query, session_id: sessionId }),
  });
}

export async function getSessions(limit = 100) {
  return request(`/api/sessions?limit=${limit}`);
}

export async function getComplianceSummary() {
  return request('/api/compliance/summary');
}



