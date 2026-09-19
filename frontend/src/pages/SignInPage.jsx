import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { SignIn } from '@clerk/clerk-react';
import Logo from '../components/Logo';
import Icon from '../components/Icon';
import { clerkAppearance } from '../config/clerkAppearance';
import { useAuth } from '../context/AuthContext';

export default function SignInPage() {
  const nav = useNavigate();
  const isKeyConfigured = Boolean(
    import.meta.env.VITE_CLERK_PUBLISHABLE_KEY &&
    !import.meta.env.VITE_CLERK_PUBLISHABLE_KEY.includes('YOUR_KEY')
  );

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const { login } = useAuth();

  const fillDemoAccount = () => {
    setEmail('analyst@corp.io');
    setPassword('SecureCipher2026!');
    setError('');
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    setError('');

    if (!email.trim()) {
      setError('Email address is required');
      return;
    }
    if (!password.trim()) {
      setError('Password is required');
      return;
    }

    setLoading(true);

    const userObj = {
      name: email.split('@')[0].replace(/[._-]/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
      email: email.trim(),
      role: 'Senior SOC Analyst',
      clearance: 'Level 4 Cryptographic Clearance',
      signedInAt: new Date().toISOString(),
    };

    // Simulate auth verification, then log in and navigate to dashboard
    setTimeout(() => {
      setLoading(false);
      login(userObj);
    }, 1000);
  };

  const handleSocialAuth = (provider) => {
    const userObj = {
      name: `${provider} Operator`,
      email: `analyst@${provider.toLowerCase()}.internal`,
      role: 'Cryptographic Forensics Officer',
      clearance: 'Level 4 Cryptographic Clearance',
      signedInAt: new Date().toISOString(),
    };
    login(userObj);
  };

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
          <SignIn
            routing="path"
            path="/sign-in"
            signUpUrl="/sign-up"
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

      <div className="auth-container">
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

        {/* Form card */}
        <div className="auth-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
            <div>
              <h1 className="auth-title">Sign in</h1>
              <p className="auth-subtitle">
                Enter your credentials to access the Security Operations Console.
              </p>
            </div>
            <button
              type="button"
              onClick={fillDemoAccount}
              style={{
                background: 'rgba(16, 185, 129, 0.08)',
                border: '1px solid rgba(16, 185, 129, 0.25)',
                color: 'var(--primary)',
                borderRadius: '6px',
                padding: '4px 8px',
                fontSize: '11px',
                fontFamily: 'var(--font-mono)',
                cursor: 'pointer',
                whiteSpace: 'nowrap',
                transition: 'background 150ms ease',
              }}
              title="Click to autofill demonstration credentials"
            >
              Demo Auto-Fill
            </button>
          </div>

          {error && (
            <div className="auth-error">
              <Icon name="alert" size={14} />
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="auth-form">
            <div className="auth-field">
              <label htmlFor="auth-email" className="auth-label">Email</label>
              <div className="auth-input-wrap">
                <Icon name="mail" size={15} className="auth-input-icon" />
                <input
                  id="auth-email"
                  type="email"
                  className="auth-input"
                  placeholder="analyst@corp.io"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  autoComplete="email"
                  autoFocus
                />
              </div>
            </div>

            <div className="auth-field">
              <div className="auth-label-row">
                <label htmlFor="auth-pw" className="auth-label">Password</label>
                <button
                  type="button"
                  className="auth-forgot"
                  onClick={() => alert('For security demonstration, credentials can be auto-filled using the "Demo Auto-Fill" button above.')}
                >
                  Forgot password?
                </button>
              </div>
              <div className="auth-input-wrap">
                <Icon name="lock" size={15} className="auth-input-icon" />
                <input
                  id="auth-pw"
                  type={showPw ? 'text' : 'password'}
                  className="auth-input auth-input-pw"
                  placeholder="••••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="current-password"
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

            <button
              type="submit"
              className={`auth-submit ${loading ? 'auth-submit-loading' : ''}`}
              disabled={loading}
            >
              {loading ? (
                <>
                  <span className="auth-spinner" />
                  Authenticating Session…
                </>
              ) : (
                'Sign In to Console'
              )}
            </button>
          </form>

          <div className="auth-divider">
            <span>or authenticate with</span>
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
          Don't have an operator account?{' '}
          <Link to="/sign-up" className="auth-link">Provision one</Link>
        </p>
        <p className="auth-security-note">
          <Icon name="shield" size={12} />
          Protected by end-to-end encrypted session protocol
        </p>
      </div>
    </div>
  );
}
