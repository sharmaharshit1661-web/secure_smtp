import { useState, useEffect } from 'react';
import { Outlet, Link } from 'react-router-dom';
import { SignedIn, SignedOut, UserButton } from '@clerk/clerk-react';
import Sidebar from './Sidebar';
import Icon from './Icon';
import { getHosts } from '../api/client';
import { clerkAppearance } from '../config/clerkAppearance';
import { useAuth } from '../context/AuthContext';

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

  const { user, logout, isClerkEnabled } = useAuth();

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
            <Link
              to="/"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                fontSize: '11px',
                fontFamily: 'var(--font-mono)',
                color: 'var(--text-secondary)',
                textDecoration: 'none',
                padding: '4px 10px',
                borderRadius: 'var(--radius-pill)',
                border: '1px solid var(--border)',
                background: 'rgba(255, 255, 255, 0.02)',
                transition: 'all 150ms ease',
              }}
              title="Return to Product Landing Page"
            >
              <Icon name="arrowRight" size={11} style={{ transform: 'rotate(180deg)' }} />
              <span>Overview</span>
            </Link>
          </div>

          <div className="flex items-center gap-3">
            <div className="status-beacon" style={{ fontFamily: 'var(--font-mono)' }}>
              <span className="status-dot status-dot-active" />
              <span style={{ color: 'var(--text-secondary)', fontWeight: 500, fontSize: '12px' }}>
                {stats.totalHosts ?? 0} hosts
              </span>
            </div>

            {/* Authentication Header Controls */}
            {isClerkEnabled ? (
              <div className="flex items-center gap-2">
                <SignedIn>
                  <UserButton
                    afterSignOutUrl="/"
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
            ) : user ? (
              <div className="flex items-center gap-2">
                <div style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  background: 'rgba(255, 255, 255, 0.03)',
                  border: '1px solid var(--border)',
                  borderRadius: '20px',
                  padding: '4px 10px 4px 6px',
                }}>
                  <div style={{
                    width: '24px',
                    height: '24px',
                    borderRadius: '50%',
                    background: 'rgba(16, 185, 129, 0.15)',
                    border: '1px solid rgba(16, 185, 129, 0.4)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '11px',
                    fontWeight: 700,
                    color: 'var(--primary)',
                    fontFamily: 'var(--font-mono)',
                  }}>
                    {(user.name || 'O').charAt(0).toUpperCase()}
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', lineHeight: 1.1 }}>
                    <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)' }}>
                      {user.name || 'Operator'}
                    </span>
                    <span style={{ fontSize: '10px', color: 'var(--primary)', fontFamily: 'var(--font-mono)' }}>
                      {user.role ? user.role.split(' ')[0] : 'SecOps'} · L4
                    </span>
                  </div>
                </div>
                <button
                  onClick={logout}
                  className="btn btn-secondary btn-sm"
                  style={{
                    padding: '4px 10px',
                    fontSize: '11px',
                    fontFamily: 'var(--font-mono)',
                    borderRadius: 'var(--radius-pill)',
                    color: 'var(--text-muted)',
                  }}
                  title="Sign out and close the dashboard"
                >
                  Sign Out
                </button>
              </div>
            ) : (
              <Link
                to="/sign-in"
                className="btn btn-primary btn-sm"
                style={{
                  padding: '5px 14px',
                  fontSize: '12px',
                  borderRadius: 'var(--radius-pill)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
              >
                <Icon name="lock" size={12} />
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