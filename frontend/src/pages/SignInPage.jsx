import { useState } from 'react';
import { Link, Navigate } from 'react-router-dom';
import { SignIn } from '@clerk/react';
import ThemeToggle from '../components/ThemeToggle';
import Logo from '../components/Logo';
import Icon from '../components/Icon';
import { useAuth } from '../context/AuthContext';

export default function SignInPage() {
  const { isClerkEnabled, isAuthenticated, offline, login, loginDemo } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showClerk, setShowClerk] = useState(false);

  if (offline || isAuthenticated) return <Navigate to="/dashboard" replace />;

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!email || !password) {
      setError('Please enter both email and password.');
      return;
    }
    setError('');
    setLoading(true);
    try {
      await login(email, password);
    } catch (err) {
      setError(err.message || 'Invalid email or password.');
    } finally {
      setLoading(false);
    }
  };

  const handleDemoAccess = async () => {
    setError('');
    setLoading(true);
    try {
      await loginDemo();
    } catch (err) {
      setError(err.message || 'Demo login failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="auth-page">
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

        {isClerkEnabled && showClerk ? (
          <div className="auth-card" style={{ padding: '0', background: 'transparent', border: 'none' }}>
            <SignIn routing="path" path="/sign-in" signUpUrl="/sign-up" fallbackRedirectUrl="/dashboard" />
            <button
              type="button"
              className="btn btn-outline btn-block"
              onClick={() => setShowClerk(false)}
              style={{ marginTop: '14px', width: '100%', padding: '9px', fontSize: '13px' }}
            >
              ← Back to Native Password Login
            </button>
          </div>
        ) : (
          <section className="auth-card">
            <h1 className="auth-title">Sign in to Secure SMTP</h1>
            <p className="auth-subtitle">Enter your credentials to access the security console.</p>

            {error && (
              <div className="auth-error" role="alert">
                <Icon name="alertTriangle" size={16} />
                <span>{error}</span>
              </div>
            )}

            <form onSubmit={handleSubmit} className="auth-form" noValidate>
              <div className="auth-field">
                <label className="auth-label" htmlFor="signin-email">
                  Operator Email
                </label>
                <div className="auth-input-wrap">
                  <span className="auth-input-icon">
                    <Icon name="mail" size={16} />
                  </span>
                  <input
                    id="signin-email"
                    type="email"
                    className="auth-input input"
                    placeholder="analyst@corp.io"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                    autoComplete="email"
                  />
                </div>
              </div>

              <div className="auth-field">
                <label className="auth-label" htmlFor="signin-password">
                  Password
                </label>
                <div className="auth-input-wrap">
                  <span className="auth-input-icon">
                    <Icon name="lock" size={16} />
                  </span>
                  <input
                    id="signin-password"
                    type="password"
                    className="auth-input input"
                    placeholder="••••••••••••"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    autoComplete="current-password"
                  />
                </div>
              </div>

              <button
                type="submit"
                className="btn btn-primary btn-block"
                disabled={loading}
                style={{ width: '100%', marginTop: '4px', padding: '11px', fontWeight: 600 }}
              >
                {loading ? 'Authenticating…' : 'Sign In →'}
              </button>

              <button
                type="button"
                className="btn btn-secondary btn-block"
                onClick={handleDemoAccess}
                disabled={loading}
                style={{ width: '100%', padding: '9px', fontSize: '12px' }}
              >
                ⚡ Instant Demo Access (1-Click)
              </button>
            </form>

            {isClerkEnabled && (
              <div style={{ marginTop: '16px', paddingTop: '16px', borderTop: '1px solid var(--border)' }}>
                <button
                  type="button"
                  className="btn btn-outline btn-block"
                  onClick={() => setShowClerk(true)}
                  style={{ width: '100%', fontSize: '12px', padding: '8px' }}
                >
                  🔒 Sign in with Enterprise SSO (Clerk)
                </button>
              </div>
            )}
          </section>
        )}

        <p className="auth-subtitle" style={{ marginTop: '20px', textAlign: 'center' }}>
          New here? <Link to="/sign-up" style={{ color: 'var(--primary)', fontWeight: 600 }}>Create an account</Link>
        </p>
      </div>
    </main>
  );
}
