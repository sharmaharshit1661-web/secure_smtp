import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { SignUp } from '@clerk/clerk-react';
import Logo from '../components/Logo';
import Icon from '../components/Icon';
import { clerkAppearance } from '../config/clerkAppearance';
import { useAuth } from '../context/AuthContext';

export default function SignUpPage() {
  const nav = useNavigate();
  const isKeyConfigured = Boolean(
    import.meta.env.VITE_CLERK_PUBLISHABLE_KEY &&
    !import.meta.env.VITE_CLERK_PUBLISHABLE_KEY.includes('YOUR_KEY')
  );

  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [role, setRole] = useState('Senior SOC Analyst');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [termsAccepted, setTermsAccepted] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const { login } = useAuth();

  const handleSubmit = (e) => {
    e.preventDefault();
    setError('');

    if (!name.trim()) {
      setError('Operator full name / call-sign is required');
      return;
    }
    if (!email.trim() || !email.includes('@')) {
      setError('A valid work email address is required');
      return;
    }
    if (password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }
    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }
    if (!termsAccepted) {
      setError('You must acknowledge the security and cryptographic audit policy');
      return;
    }

    setLoading(true);

    const userObj = {
      name: name.trim(),
      email: email.trim(),
      role,
      clearance: 'Level 4 Cryptographic Clearance',
      joinedAt: new Date().toISOString(),
    };

    setTimeout(() => {
      setLoading(false);
      login(userObj);
    }, 1200);
  };

  const handleSocialAuth = (provider) => {
    const userObj = {
      name: `${provider} Operator`,
      email: `analyst@${provider.toLowerCase()}.internal`,
      role: 'Cryptographic Forensics Officer',
      clearance: 'Level 4 Cryptographic Clearance',
      joinedAt: new Date().toISOString(),
    };
    login(userObj);
  };

  // If live Clerk instance is explicitly configured
  if (isKeyConfigured) {
    return (
      <div className="auth-page">
        <div className="auth-ambient" aria-hidden="true" />
        <div className="auth-container">
          <Link to="/" className="auth-back">
            <Icon name="arrowRight" size={14} style={{ transform: 'rotate(180deg)' }} />
            Back
          </Link>
          <div className="auth-brand">
            <Logo size={32} />
            <span className="auth-brand-name">Secure SMTP</span>
          </div>
          <SignUp
            routing="path"
            path="/sign-up"
            signInUrl="/sign-in"
            fallbackRedirectUrl="/dashboard"
            appearance={clerkAppearance}
          />
        </div>
      </div>
    );
  }

  return (
    <div className="auth-page">
      {/* Ambient glow */}
      <div className="auth-ambient" aria-hidden="true" />

      <div className="auth-container" style={{ maxWidth: '460px' }}>
        {/* Back to landing */}
        <Link to="/" className="auth-back">
          <Icon name="arrowRight" size={14} style={{ transform: 'rotate(180deg)' }} />
          Back to Overview
        </Link>

        {/* Brand */}
        <div className="auth-brand">
          <Logo size={32} />
          <span className="auth-brand-name">Secure SMTP</span>
        </div>

        {/* Registration Card */}
        <div className="auth-card">
          <h1 className="auth-title">Provision Operator</h1>
          <p className="auth-subtitle">
            Create an authorized operator account for the Cryptographic Security Operations Console.
          </p>

          {error && (
            <div className="auth-error">
              <Icon name="alert" size={14} />
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="auth-form">
            <div className="auth-field">
              <label htmlFor="reg-name" className="auth-label">Call-Sign / Full Name</label>
              <div className="auth-input-wrap">
                <Icon name="user" size={15} className="auth-input-icon" />
                <input
                  id="reg-name"
                  type="text"
                  className="auth-input"
                  placeholder="e.g. Alex Vance"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  autoComplete="name"
                  autoFocus
                />
              </div>
            </div>

            <div className="auth-field">
              <label htmlFor="reg-email" className="auth-label">Work Email</label>
              <div className="auth-input-wrap">
                <Icon name="mail" size={15} className="auth-input-icon" />
                <input
                  id="reg-email"
                  type="email"
                  className="auth-input"
                  placeholder="analyst@corp.io"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  autoComplete="email"
                />
              </div>
            </div>

            <div className="auth-field">
              <label htmlFor="reg-role" className="auth-label">Clearance Role</label>
              <div className="auth-input-wrap">
                <Icon name="shield" size={15} className="auth-input-icon" />
                <select
                  id="reg-role"
                  className="auth-input"
                  value={role}
                  onChange={(e) => setRole(e.target.value)}
                  style={{
                    appearance: 'none',
                    cursor: 'pointer',
                    backgroundImage: 'url("data:image/svg+xml;charset=US-ASCII,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20width%3D%2214%22%20height%3D%2214%22%20viewBox%3D%220%200%2024%2024%22%20fill%3D%22none%22%20stroke%3D%22%237A7A85%22%20stroke-width%3D%222%22%20stroke-linecap%3D%22round%22%20stroke-linejoin%3D%22round%22%3E%3Cpolyline%20points%3D%226%209%2012%2015%2018%209%22%3E%3C%2Fpolyline%3E%3C%2Fsvg%3E")',
                    backgroundRepeat: 'no-repeat',
                    backgroundPosition: 'right 12px center',
                    paddingRight: '36px',
                  }}
                >
                  <option value="Senior SOC Analyst" style={{ background: '#0D0D0E', color: '#E8E8EC' }}>Senior SOC Analyst</option>
                  <option value="Cryptographic Forensics Officer" style={{ background: '#0D0D0E', color: '#E8E8EC' }}>Cryptographic Forensics Officer</option>
                  <option value="DevSecOps Compliance Auditor" style={{ background: '#0D0D0E', color: '#E8E8EC' }}>DevSecOps Compliance Auditor</option>
                  <option value="Incident Response Lead" style={{ background: '#0D0D0E', color: '#E8E8EC' }}>Incident Response Lead</option>
                </select>
              </div>
            </div>

            <div className="auth-field">
              <label htmlFor="reg-pw" className="auth-label">Password</label>
              <div className="auth-input-wrap">
                <Icon name="lock" size={15} className="auth-input-icon" />
                <input
                  id="reg-pw"
                  type={showPw ? 'text' : 'password'}
                  className="auth-input auth-input-pw"
                  placeholder="Minimum 8 characters"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="new-password"
                />
                <button
                  type="button"
                  className="auth-pw-toggle"
                  onClick={() => setShowPw(!showPw)}
                  aria-label={showPw ? 'Hide password' : 'Show password'}
                  tabIndex={-1}
                >
                  <Icon name={showPw ? 'x' : 'search'} size={14} />
                </button>
              </div>
            </div>

            <div className="auth-field">
              <label htmlFor="reg-confirm-pw" className="auth-label">Confirm Password</label>
              <div className="auth-input-wrap">
                <Icon name="lock" size={15} className="auth-input-icon" />
                <input
                  id="reg-confirm-pw"
                  type={showPw ? 'text' : 'password'}
                  className="auth-input auth-input-pw"
                  placeholder="Repeat your password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  autoComplete="new-password"
                />
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '8px', marginTop: '2px' }}>
              <input
                id="reg-terms"
                type="checkbox"
                checked={termsAccepted}
                onChange={(e) => setTermsAccepted(e.target.checked)}
                style={{
                  marginTop: '3px',
                  accentColor: 'var(--primary)',
                  cursor: 'pointer',
                }}
              />
              <label htmlFor="reg-terms" style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.4, cursor: 'pointer' }}>
                I acknowledge authorization under NIST SP 800-52r2 and enterprise cryptographic audit governance.
              </label>
            </div>

            <button
              type="submit"
              className={`auth-submit ${loading ? 'auth-submit-loading' : ''}`}
              disabled={loading}
              style={{ marginTop: '10px' }}
            >
              {loading ? (
                <>
                  <span className="auth-spinner" />
                  Provisioning Operator Profile…
                </>
              ) : (
                'Create Operator Account'
              )}
            </button>
          </form>

          <div className="auth-divider">
            <span>or instant provision with</span>
          </div>

          <div className="auth-social-row">
            <button className="auth-social" onClick={() => handleSocialAuth('Google')}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" /><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" /><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" /><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" /></svg>
              Google
            </button>
            <button className="auth-social" onClick={() => handleSocialAuth('GitHub')}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" /></svg>
              GitHub
            </button>
          </div>
        </div>

        {/* Footer */}
        <p className="auth-footer-text">
          Already have an authorized account?{' '}
          <Link to="/sign-in" className="auth-link">Sign in here</Link>
        </p>
        <p className="auth-security-note">
          <Icon name="shield" size={12} />
          Protected by end-to-end encrypted session protocol
        </p>
      </div>
    </div>
  );
}
