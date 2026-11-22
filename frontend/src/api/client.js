import { errorMessage, fetchWithDeadline } from './transport.js';
/**
 * Fetch wrapper for the Secure SMTP FastAPI backend.
 */

// Default to empty string so local Vite dev proxy (/api -> :8000) is leveraged seamlessly without CORS hurdles,
// while still supporting explicit VITE_API_BASE for cross-origin deployments.
const API_BASE = import.meta.env?.VITE_API_BASE ?? '';
let tokenProvider = null;
export function configureTokenProvider(provider) { tokenProvider = provider; }
export async function getAccessToken() {
  const token = await tokenProvider?.();
  if (!token) throw new Error('Sign in to continue.');
  return token;
}
export function getLiveSocketUrl() {
  const url = new URL(API_BASE || window.location.origin, window.location.origin);
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
  url.pathname = '/ws/live';
  return url.toString();
}

async function request(path, options = {}) {
  const url = `${API_BASE}${path}`;
  const res = await fetchWithDeadline(url, {
    ...options,
    headers: {
      'Authorization': `Bearer ${await getAccessToken()}`,
      ...options.headers,
    },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    const error = new Error(errorMessage(body.detail, res.status));
    error.status = res.status;
    throw error;
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

export async function getAnalysisStatus(jobId, options = {}) {
  return request(`/api/analyze/${jobId}/status`, options);
}

export async function uploadPcap(file) {
  const formData = new FormData();
  formData.append('file', file);
  const url = `${API_BASE}/api/analyze`;
  const res = await fetchWithDeadline(url, {
    method: 'POST',
    body: formData,
    headers: {
      'Authorization': `Bearer ${await getAccessToken()}`,
    },
  }, 180000);
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(errorMessage(body.detail, res.status));
  }
  return res.json();
}

export async function downloadReport(jobId, format) {
  const response = await fetchWithDeadline(`${API_BASE}/api/reports/${encodeURIComponent(jobId)}.${format}`, {
    headers: { Authorization: `Bearer ${await getAccessToken()}` },
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(errorMessage(body.detail, response.status));
  }
  const url = URL.createObjectURL(await response.blob());
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `secure_smtp_${jobId}.${format}`;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 60000);
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




export const getIdentity = () => request('/api/identity');
export const getAgents = () => request('/api/agents');
export const getAssessments = () => request('/api/assessments');
export const getOperations = () => request('/api/operations');
export const getGraphWeaknesses = () => request('/api/graph/weaknesses');
export const getRemediations = () => request('/api/remediations');
export const createAgent = name => request('/api/agents', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({name}) });
export const revokeAgent = id => request(`/api/agents/${id}/revoke`, { method: 'POST' });
export const deleteAssessment = id => request(`/api/assessments/${id}`, { method: 'DELETE' });
export const retryIntegrations = id => request(`/api/assessments/${id}/retry-integrations`, { method: 'POST' });
export const trackRemediation = (session_id, rule_id) => request('/api/remediations', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({session_id,rule_id}) });

export async function loginUser(email, password) {
  const res = await fetch(`${API_BASE}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.detail || `Sign in failed (${res.status})`);
  }
  return res.json();
}

export async function registerUser({ name, email, password, role = 'admin' }) {
  const res = await fetch(`${API_BASE}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, email, password, role }),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.detail || `Registration failed (${res.status})`);
  }
  return res.json();
}

export async function demoLogin() {
  const res = await fetch(`${API_BASE}/api/auth/demo`, {
    method: 'POST',
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.detail || `Demo access failed (${res.status})`);
  }
  return res.json();
}
