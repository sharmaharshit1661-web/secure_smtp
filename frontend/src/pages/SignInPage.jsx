import { useState } from 'react';
import { Link, Navigate, useNavigate } from 'react-router-dom';
import { SignIn, OrganizationSwitcher } from '@clerk/clerk-react';
import ThemeToggle from '../components/ThemeToggle';
import Logo from '../components/Logo';
import Icon from '../components/Icon';
import { useAuth } from '../context/AuthContext';

export default function SignInPage() {
  const { isClerkEnabled, isAuthenticated, offline, login } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('analyst@corp.io');
  const [role, setRole] = useState('admin');

  if (offline) return <Navigate to="/dashboard" replace />;
  if (isAuthenticated) return <Navigate to="/dashboard" replace />;

  const handleLocalSignIn = (e) => {
    if (e) e.preventDefault();
    login({
      name: role === 'admin' ? 'SOC Lead Administrator' : 'Security Analyst',
      email: email.trim() || 'analyst@corp.io',
      role: role,
      clearance: role === 'admin' ? 'Level 4 SOC Administrator' : 'Level 2 Analyst',
    });
    navigate('/dashboard');
  };

  return (
    <div className="auth-page">
      <div className="auth-container">
        <div className="auth-theme-control">
          <ThemeToggle />
        </div>
        <Link to="/" className="auth-back">
          Back to overview
        </Link>
        <div className="auth-brand">
          <Logo size={32} />
          <span className="auth-brand-name">Secure SMTP</span>
        </div>

        {!isClerkEnabled ? (
          <div className="auth-card">
            <div style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              padding: '4px 10px',
              borderRadius: 'var(--radius-pill)',
              background: 'rgba(16, 185, 129, 0.12)',
              border: '1px solid rgba(16, 185, 129, 0.3)',
              color: 'var(--primary)',
              fontSize: '11px',
              fontFamily: 'var(--font-mono)',
              fontWeight: 600,
              marginBottom: '16px',
            }}>
              <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: 'var(--primary)' }} />
              Local / Evaluation Mode
            </div>
            <h1 className="auth-title">Sign in to Secure SMTP</h1>
            <p className="auth-subtitle">
              Verified pilot mode. Sign in with SOC credentials or use instant 1-click access.
            </p>

            <form onSubmit={handleLocalSignIn} className="auth-form">
              <div className="auth-field">
                <label className="auth-label" htmlFor="email-input">Operator Email</label>
                <div className="auth-input-wrap">
                  <span className="auth-input-icon">
                    <Icon name="mail" size={16} />
                  </span>
                  <input
                    id="email-input"
                    type="email"
                    className="auth-input input"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="analyst@corp.io"
                    required
                  />
                </div>
              </div>

              <div className="auth-field">
                <label className="auth-label" htmlFor="role-select">Access Clearance & Role</label>
                <select
                  id="role-select"
                  className="input"
                  value={role}
                  onChange={(e) => setRole(e.target.value)}
                  style={{ width: '100%', padding: '10px 12px' }}
                >
                  <option value="admin">SOC Lead Administrator (Full Controls & Live Lab)</option>
                  <option value="member">Security Analyst (Monitoring & Compliance Only)</option>
                </select>
              </div>

              <button
                type="submit"
                className="btn btn-primary btn-block"
                style={{ width: '100%', padding: '11px', marginTop: '6px', fontWeight: 600 }}
              >
                Sign In to Dashboard →
              </button>

              <button
                type="button"
                className="btn btn-secondary btn-block"
                style={{ width: '100%', padding: '9px', fontSize: '12px' }}
                onClick={() => {
                  login({
                    name: 'SOC Lead Administrator',
                    email: 'analyst@corp.io',
                    role: 'admin',
                    clearance: 'Level 4 SOC Administrator',
                  });
                  navigate('/dashboard');
                }}
              >
                ⚡ Instant Demo Access (1-Click)
              </button>
            </form>
          </div>
        ) : isAuthenticated ? (
          <div className="auth-card">
            <h1 className="auth-title">Select your organization</h1>
            <p className="auth-subtitle">Use the pilot organization your administrator invited you to.</p>
            <OrganizationSwitcher hidePersonal />
            <Link className="btn btn-primary" to="/dashboard" style={{ marginTop: '16px', display: 'block', textAlign: 'center' }}>
              Open dashboard
            </Link>
          </div>
        ) : (
          <SignIn routing="path" path="/sign-in" signUpUrl="/sign-up" fallbackRedirectUrl="/dashboard" />
        )}
      </div>
    </div>
  );
}
