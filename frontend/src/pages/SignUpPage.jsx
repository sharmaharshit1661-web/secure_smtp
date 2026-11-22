import { useState } from 'react';
import { Link, Navigate } from 'react-router-dom';
import { SignUp } from '@clerk/react';
import ThemeToggle from '../components/ThemeToggle';
import Logo from '../components/Logo';
import Icon from '../components/Icon';
import { useAuth } from '../context/AuthContext';

export default function SignUpPage() {
  const { isClerkEnabled, isAuthenticated, offline, register } = useAuth();
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('admin');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showClerk, setShowClerk] = useState(false);

  if (offline || isAuthenticated) return <Navigate to="/dashboard" replace />;

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!name || !email || !password) {
      setError('Please fill out all fields.');
      return;
    }
    if (password.length < 6) {
      setError('Password must be at least 6 characters.');
      return;
    }
    setError('');
    setLoading(true);
    try {
      await register({ name, email, password, role });
    } catch (err) {
      setError(err.message || 'Account creation failed.');
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
            <SignUp routing="path" path="/sign-up" signInUrl="/sign-in" fallbackRedirectUrl="/dashboard" />
            <button
              type="button"
              className="btn btn-outline btn-block"
              onClick={() => setShowClerk(false)}
              style={{ marginTop: '14px', width: '100%', padding: '9px', fontSize: '13px' }}
            >
              ← Back to Native Registration
            </button>
          </div>
        ) : (
          <section className="auth-card">
            <h1 className="auth-title">Create an Account</h1>
            <p className="auth-subtitle">Set up your security operator credentials in Secure SMTP.</p>

            {error && (
              <div className="auth-error" role="alert">
                <Icon name="alertTriangle" size={16} />
                <span>{error}</span>
              </div>
            )}

            <form onSubmit={handleSubmit} className="auth-form" noValidate>
              <div className="auth-field">
                <label className="auth-label" htmlFor="signup-name">
                  Full Name
                </label>
                <div className="auth-input-wrap">
                  <span className="auth-input-icon">
                    <Icon name="user" size={16} />
                  </span>
                  <input
                    id="signup-name"
                    type="text"
                    className="auth-input input"
                    placeholder="Alex Morgan"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    required
                    autoComplete="name"
                  />
                </div>
              </div>

              <div className="auth-field">
                <label className="auth-label" htmlFor="signup-email">
                  Operator Email
                </label>
                <div className="auth-input-wrap">
                  <span className="auth-input-icon">
                    <Icon name="mail" size={16} />
                  </span>
                  <input
                    id="signup-email"
                    type="email"
                    className="auth-input input"
                    placeholder="alex@corp.io"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                    autoComplete="email"
                  />
                </div>
              </div>

              <div className="auth-field">
                <label className="auth-label" htmlFor="signup-password">
                  Password (min 6 characters)
                </label>
                <div className="auth-input-wrap">
                  <span className="auth-input-icon">
                    <Icon name="lock" size={16} />
                  </span>
                  <input
                    id="signup-password"
                    type="password"
                    className="auth-input input"
                    placeholder="••••••••••••"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    autoComplete="new-password"
                  />
                </div>
              </div>

              <div className="auth-field">
                <label className="auth-label" htmlFor="signup-role">
                  Clearance Level
                </label>
                <select
                  id="signup-role"
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
                disabled={loading}
                style={{ width: '100%', marginTop: '6px', padding: '11px', fontWeight: 600 }}
              >
                {loading ? 'Creating Account…' : 'Create Account & Sign In →'}
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
                  🔒 Register with Enterprise SSO (Clerk)
                </button>
              </div>
            )}
          </section>
        )}

        <p className="auth-subtitle" style={{ marginTop: '20px', textAlign: 'center' }}>
          Already have an account? <Link to="/sign-in" style={{ color: 'var(--primary)', fontWeight: 600 }}>Sign in</Link>
        </p>
      </div>
    </main>
  );
}
