import { useEffect, useRef } from 'react';

/** Poll without overlap, pause hidden tabs, and refresh when connectivity returns. */
export default function usePolling(callback, interval = 15000) {
  const latest = useRef(callback);
  useEffect(() => { latest.current = callback; });
  useEffect(() => {
    let active = true;
    let pending = false;
    const refresh = async () => {
      if (!active || pending || document.hidden) return;
      pending = true;
      try { await latest.current(); } finally { pending = false; }
    };
    const timer = setInterval(refresh, interval);
    window.addEventListener('online', refresh);
    document.addEventListener('visibilitychange', refresh);
    return () => {
      active = false;
      clearInterval(timer);
      window.removeEventListener('online', refresh);
      document.removeEventListener('visibilitychange', refresh);
    };
  }, [interval]);
}
