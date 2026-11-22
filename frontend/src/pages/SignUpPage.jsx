import { Link, Navigate } from 'react-router-dom';
import { SignUp, OrganizationSwitcher } from '@clerk/clerk-react';
import ThemeToggle from '../components/ThemeToggle';
import Logo from '../components/Logo';
import { useAuth } from '../context/AuthContext';

export default function SignUpPage() {
  const { isClerkEnabled, isAuthenticated, offline } = useAuth();
  if (offline) return <Navigate to="/dashboard" replace />;
  if (isAuthenticated) return <Navigate to="/dashboard" replace />;

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
            <h1 className="auth-title">Sign up for Secure SMTP</h1>
            <p className="auth-subtitle">
              Evaluation pilot environment. You can sign in directly using built-in credentials.
            </p>
            <Link
              to="/sign-in"
              className="btn btn-primary btn-block"
              style={{ marginTop: '16px', display: 'block', textAlign: 'center' }}
            >
              Go to Sign In →
            </Link>
          </div>
        ) : isAuthenticated ? (
          <div className="auth-card">
            <h1 className="auth-title">Select your organization</h1>
            <p className="auth-subtitle">Use the pilot organization your administrator invited you to.</p>
            <OrganizationSwitcher hidePersonal />
            <Link
              className="btn btn-primary"
              to="/dashboard"
              style={{ marginTop: '16px', display: 'block', textAlign: 'center' }}
            >
              Open dashboard
            </Link>
          </div>
        ) : (
          <SignUp routing="path" path="/sign-up" signInUrl="/sign-in" fallbackRedirectUrl="/dashboard" />
        )}
      </div>
    </div>
  );
}
