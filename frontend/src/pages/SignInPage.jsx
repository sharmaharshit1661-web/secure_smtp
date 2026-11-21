import { useState } from 'react';
import { Link } from 'react-router-dom';
import { SignIn } from '@clerk/clerk-react';
import Logo from '../components/Logo';
import { clerkAppearance } from '../config/clerkAppearance';
import { useAuth } from '../context/AuthContext';

export default function SignInPage() {
  const { login, isClerkEnabled } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  async function submit(event) {
    event.preventDefault();
    setLoading(true);
    setError('');
    try { await login({ email, password }); }
    catch (err) { setError(err.message || 'Unable to sign in. Please try again.'); }
    finally { setPassword(''); setLoading(false); }
  }
  return <div className="auth-page">
    <div className="auth-ambient" aria-hidden="true" />
    <div className="auth-container">
      <Link to="/" className="auth-back">Back to overview</Link>
      <div className="auth-brand"><Logo size={32} /><span className="auth-brand-name">Secure SMTP</span></div>
      {isClerkEnabled ? <SignIn routing="path" path="/sign-in" signUpUrl="/sign-up" fallbackRedirectUrl="/dashboard" appearance={clerkAppearance} /> :
        <div className="auth-card">
          <h1 className="auth-title">Sign in</h1>
          <p className="auth-subtitle">Use the operator account provided by your administrator.</p>
          {error && <div className="auth-error" role="alert">{error}</div>}
          <form onSubmit={submit} className="auth-form">
            <div className="auth-field"><label htmlFor="auth-email" className="auth-label">Email</label>
              <input id="auth-email" className="auth-input" type="email" required maxLength={254} autoComplete="username" value={email} onChange={e => setEmail(e.target.value)} /></div>
            <div className="auth-field"><label htmlFor="auth-pw" className="auth-label">Password</label>
              <input id="auth-pw" className="auth-input" type="password" required maxLength={1024} autoComplete="current-password" value={password} onChange={e => setPassword(e.target.value)} /></div>
            <button className="auth-submit" disabled={loading} type="submit">{loading ? 'Signing in…' : 'Sign in'}</button>
          </form>
          <p className="auth-subtitle">For account access or a password reset, contact your administrator.</p>
        </div>}
    </div>
  </div>;
}
