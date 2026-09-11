import { useState, useEffect } from 'react';
import { Outlet, Link } from 'react-router-dom';
import { SignedIn, SignedOut, UserButton } from '@clerk/clerk-react';
import Sidebar from './Sidebar';
import Icon from './Icon';
import { getHosts } from '../api/client';
import { clerkAppearance } from '../config/clerkAppearance';

export default function Layout() {
  const [stats, setStats] = useState({});
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [sidebarWidth, setSidebarWidth] = useState(() => {
    try {
      const saved = localStorage.getItem('secure_smtp_sidebar_width');
      if (saved) {
        const val = parseInt(saved, 10);
        if (!isNaN(val) && val >= 200 && val <= 480) return val;
      }
    } catch {
      // ignore
    }
    return 264;
  });

  const handleWidthChange = (newWidth) => {
    setSidebarWidth(newWidth);
    try {
      localStorage.setItem('secure_smtp_sidebar_width', String(newWidth));
    } catch {
      // ignore
    }
  };

  const isKeyConfigured = Boolean(
    import.meta.env.VITE_CLERK_PUBLISHABLE_KEY &&
    !import.meta.env.VITE_CLERK_PUBLISHABLE_KEY.includes('YOUR_KEY')
  );

  useEffect(() => {
    getHosts()
      .then((hosts) => {
        const sorted = [...hosts].sort((a, b) => (b.aggregate_risk_score || 0) - (a.aggregate_risk_score || 0));
        const totalHosts = sorted.length;
        const totalSessions = sorted.reduce((s, h) => s + (h.session_count || 0), 0);
        const criticalHosts = sorted.filter((h) => (h.aggregate_risk_score || 0) >= 75).length;
        setStats({ totalHosts, totalSessions, criticalHosts });
      })
      .catch(() => setStats({ totalHosts: 0, totalSessions: 0, criticalHosts: 0 }));
  }, []);

  return (
    <div className="app-layout" style={{ '--sidebar-width': `${sidebarWidth}px` }}>
      <Sidebar
        isOpen={sidebarOpen}
        onClose={() => setSidebarOpen(false)}
        width={sidebarWidth}
        onWidthChange={handleWidthChange}
      />
      <div className="app-main">
        <header className="app-header">
          <div className="flex items-center gap-3">
            <button
              className="btn btn-sm mobile-menu-toggle"
              onClick={() => setSidebarOpen(!sidebarOpen)}
              aria-label="Toggle navigation"
              style={{ display: 'none', padding: '6px 10px' }}
            >
              <Icon name="menu" size={16} />
            </button>
          </div>

          <div className="flex items-center gap-3">
            <div className="status-beacon" style={{ fontFamily: 'var(--font-mono)' }}>
              <span className="status-dot status-dot-active" />
              <span style={{ color: 'var(--text-secondary)', fontWeight: 500, fontSize: '12px' }}>
                {stats.totalHosts ?? 0} hosts
              </span>
            </div>

            {/* Clerk Authentication Header Controls */}
            {isKeyConfigured ? (
              <div className="flex items-center gap-2">
                <SignedIn>
                  <UserButton
                    afterSignOutUrl="/sign-in"
                    appearance={clerkAppearance}
                  />
                </SignedIn>
                <SignedOut>
                  <Link
                    to="/sign-in"
                    className="btn btn-primary btn-sm"
                    style={{
                      padding: '5px 14px',
                      fontSize: '12px',
                      borderRadius: 'var(--radius-pill)',
                    }}
                  >
                    Sign In
                  </Link>
                </SignedOut>
              </div>
            ) : (
              <Link
                to="/sign-in"
                className="btn btn-secondary btn-sm"
                style={{
                  padding: '5px 12px',
                  fontSize: '11px',
                  fontFamily: 'var(--font-mono)',
                  borderRadius: 'var(--radius-pill)',
                }}
              >
                Sign In
              </Link>
            )}
          </div>
        </header>

        <main className="app-content">
          <Outlet />
        </main>

        <footer className="app-footer">
          <div className="flex items-center gap-3">
            <span style={{ color: 'var(--sev-clean)', fontSize: '8px' }}>●</span>
            <span>Cryptographic Posture Intelligence Active</span>
          </div>
          <div>
            <a
              href="https://github.com/sharmaharshit1661-web"
              target="_blank"
              rel="noopener noreferrer"
              className="app-footer-link"
            >
              @sharmaharshit1661
            </a>
          </div>
        </footer>
      </div>
    </div>
  );
}