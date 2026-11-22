/** User-facing API errors, including FastAPI field validation responses. */
export function errorMessage(detail, status) {
  if (typeof detail === 'string' && detail.trim()) return detail;
  if (Array.isArray(detail)) {
    const messages = detail.map(item => {
      const field = Array.isArray(item?.loc) ? item.loc.filter(x => x !== 'body').join('.') : '';
      return typeof item?.msg === 'string' ? `${field ? field + ': ' : ''}${item.msg}` : '';
    }).filter(Boolean);
    if (messages.length) return messages.join(' · ');
  }
  if (status === 401) return 'Your session expired. Sign in again.';
  if (status === 403) return 'Your account does not have permission for this action.';
  if (status === 429) return 'The service is busy. Wait a moment and try again.';
  if (status >= 500) return 'The service is unavailable. Please try again shortly.';
  return `Request failed (${status}). Please try again.`;
}

export async function fetchWithDeadline(url, options = {}, timeoutMs = 30000) {
  const controller = new AbortController();
  const cancel = () => controller.abort(options.signal?.reason);
  let timedOut = false;
  if (options.signal?.aborted) cancel();
  options.signal?.addEventListener('abort', cancel, {once: true});
  const timer = setTimeout(() => { timedOut = true; controller.abort(); }, timeoutMs);
  try {
    return await fetch(url, {...options, signal: controller.signal});
  } catch (error) {
    if (timedOut) throw new Error('The request timed out. Check your connection and try again.');
    if (controller.signal.aborted) throw error;
    throw new Error('Could not connect to the service. Check your connection and try again.');
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener('abort', cancel);
  }
}
