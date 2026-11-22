import { useState, useEffect } from 'react';
import { Outlet, Link, useLocation } from 'react-router-dom';
import { SignedIn, SignedOut, UserButton, OrganizationSwitcher } from '@clerk/clerk-react';
import Sidebar from './Sidebar';
import Icon from './Icon';
import { getHosts } from '../api/client';
import ThemeToggle from './ThemeToggle';
import { useAuth } from '../context/AuthContext';

export default function Layout() {
  const [stats, setStats] = useState(null);
  const [statusError, setStatusError] = useState(false);
  const { pathname } = useLocation();
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
    if (!sidebarOpen) return;
    const previousFocus = document.activeElement;
    const navigation = document.getElementById('console-navigation');
    const focusable = () => [...navigation.querySelectorAll('a[href],button:not(:disabled)')].filter(element => element.getClientRects().length);
    focusable()[0]?.focus();
    const overflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    const handleKey = event => {
      if (event.key === 'Escape') { event.preventDefault(); setSidebarOpen(false); }
      if (event.key === 'Tab') {
        const items = focusable();
        const first = items[0]; const last = items.at(-1);
        if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
      }
    };
    const query = window.matchMedia('(max-width: 768px)');
    const closeOnDesktop = () => { if (!query.matches) setSidebarOpen(false); };
    window.addEventListener('keydown', handleKey);
    query.addEventListener('change', closeOnDesktop);
    return () => {
      window.removeEventListener('keydown', handleKey);
      query.removeEventListener('change', closeOnDesktop);
      document.body.style.overflow = overflow;
      previousFocus?.focus?.();
    };
  }, [sidebarOpen]);

  useEffect(() => {
    getHosts()
      .then((hosts) => {
        const sorted = [...hosts].sort((a, b) => (b.aggregate_risk_score || 0) - (a.aggregate_risk_score || 0));
        const totalHosts = sorted.length;
        const totalSessions = sorted.reduce((s, h) => s + (h.session_count || 0), 0);
        const criticalHosts = sorted.filter((h) => (h.aggregate_risk_score || 0) >= 75).length;
        setStats({ totalHosts, totalSessions, criticalHosts });
      })
      .catch(() => setStatusError(true));
  }, []);

  return (
    <div className="app-layout" style={{ '--sidebar-width': `${sidebarWidth}px` }}>
      <a className="skip-link" href="#workspace-content">Skip to workspace</a>
      <Sidebar
        isOpen={sidebarOpen}
        onClose={() => setSidebarOpen(false)}
        width={sidebarWidth}
        onWidthChange={handleWidthChange}
      />
      {sidebarOpen && <button tabIndex={-1} className="navigation-backdrop" aria-label="Close navigation" onClick={() => setSidebarOpen(false)} />}
      <div className="app-main" inert={sidebarOpen}>
        <header className="app-header">
          <div className="flex items-center gap-3">
            <button
              className="btn btn-sm mobile-menu-toggle"
              onClick={() => setSidebarOpen(!sidebarOpen)}
              aria-label="Toggle navigation"
              aria-expanded={sidebarOpen}
              aria-controls="console-navigation"
              style={{ padding: '6px 10px' }}
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
              <span>Product home</span>
            </Link>
          </div>

          <div className="flex items-center gap-3">
            <div className="status-beacon" style={{ fontFamily: 'var(--font-mono)' }}>
              <span className="status-dot" style={{ background: statusError ? 'var(--sev-high)' : stats ? 'var(--sev-clean)' : 'var(--text-muted)' }} />
              <span style={{ color: 'var(--text-secondary)', fontWeight: 500, fontSize: '12px' }}>
                {statusError ? 'API unavailable' : stats ? `${stats.totalHosts} hosts` : 'Connecting…'}
              </span>
            </div>

            <ThemeToggle />
            {/* Authentication Header Controls */}
            {isClerkEnabled ? (
              <div className="flex items-center gap-2">
                <SignedIn>
                  <OrganizationSwitcher hidePersonal />
                  <UserButton
                    afterSignOutUrl="/"

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
                      {isClerkEnabled ? 'Signed in' : 'Local account'}
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

        <main className="app-content" id="workspace-content" key={pathname} tabIndex={-1}>
          <Outlet />
        </main>

        <footer className="app-footer">
          <div className="flex items-center gap-3">
            <span style={{ color: 'var(--sev-clean)', fontSize: '8px' }}>●</span>
            <span>Secure SMTP · Cryptographic posture intelligence</span>
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
