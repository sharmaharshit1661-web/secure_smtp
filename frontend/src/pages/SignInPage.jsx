import { Link, Navigate } from 'react-router-dom';
import { SignIn, OrganizationSwitcher } from '@clerk/clerk-react';
import ThemeToggle from '../components/ThemeToggle';
import Logo from '../components/Logo';
import { useAuth } from '../context/AuthContext';

export default function SignInPage() {
  const { isClerkEnabled, isAuthenticated, offline } = useAuth();
  if (offline) return <Navigate to="/dashboard" replace />;
  return <div className="auth-page"><div className="auth-container">
    <div className="auth-theme-control"><ThemeToggle /></div>
    <Link to="/" className="auth-back">Back to overview</Link>
    <div className="auth-brand"><Logo size={32} /><span className="auth-brand-name">Secure SMTP</span></div>
    {!isClerkEnabled ? <div className="auth-card"><h1 className="auth-title">Sign-in unavailable</h1><p className="auth-subtitle">Verified sign-in must be configured before the pilot can open. Contact your administrator.</p></div> : isAuthenticated ? <div className="auth-card"><h1 className="auth-title">Select your organization</h1><p className="auth-subtitle">Use the pilot organization your administrator invited you to.</p><OrganizationSwitcher hidePersonal /><Link className="btn btn-primary" to="/dashboard">Open dashboard</Link></div> : <SignIn routing="path" path="/sign-in" signUpUrl="/sign-up" fallbackRedirectUrl="/dashboard" />}
  </div></div>;
}
