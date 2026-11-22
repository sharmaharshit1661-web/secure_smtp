export async function waitForAnalysis(jobId, { getStatus, signal, onStatus = () => {}, delay = abortableDelay, attempts = 120 } = {}) {
  for (let attempt = 0; attempt < attempts; attempt++) {
    signal?.throwIfAborted();
    const job = await getStatus(jobId, { signal });
    signal?.throwIfAborted();
    onStatus(job.status);
    if (job.status === 'done') return job;
    if (job.status === 'failed') throw new Error(job.error_message || 'Analysis failed. Try another capture.');
    if (attempt + 1 < attempts) await delay(1500, signal);
  }
  throw new Error('Analysis is still running. Refresh the job status before exporting a report.');
}
function abortableDelay(ms, signal) {
  return new Promise((resolve, reject) => {
    signal?.throwIfAborted();
    const done = () => { signal?.removeEventListener('abort', abort); resolve(); };
    const timer = setTimeout(done, ms);
    const abort = () => { clearTimeout(timer); reject(signal.reason); };
    signal?.addEventListener('abort', abort, { once: true });
  });
}
