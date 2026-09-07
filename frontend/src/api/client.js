/**
 * Fetch wrapper for the Secure SMTP FastAPI backend.
 */

// Default to empty string so local Vite dev proxy (/api -> :8000) is leveraged seamlessly without CORS hurdles,
// while still supporting explicit VITE_API_BASE for cross-origin deployments.
const API_BASE = import.meta.env.VITE_API_BASE ?? '';
const API_KEY = import.meta.env.VITE_API_KEY || 'securesmtp_live_secret_key';

async function request(path, options = {}) {
  const url = `${API_BASE}${path}`;
  const res = await fetch(url, {
    ...options,
    headers: {
      'X-API-Key': API_KEY,
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
    body: formData,
    headers: {
      'X-API-Key': API_KEY,
    },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || `Upload failed: ${res.status}`);
  }
  return res.json();
}

export function getReportUrl(jobId, format) {
  return `${API_BASE}/api/reports/${jobId}.${format}?api_key=${encodeURIComponent(API_KEY)}`;
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
