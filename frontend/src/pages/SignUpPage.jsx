import { Link, Navigate } from 'react-router-dom';
import { SignUp } from '@clerk/react';
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
        <h1 className="sr-only">Sign up for Secure SMTP</h1>

        {isClerkEnabled ? (
          <SignUp routing="path" path="/sign-up" signInUrl="/sign-in" fallbackRedirectUrl="/dashboard" />
        ) : <section className="auth-card"><h1 className="auth-title">Registration is not configured</h1>
          <p className="auth-subtitle">Your administrator must configure Clerk to enable account registration.</p></section>}
        <p className="auth-subtitle">Already have an account? <Link to="/sign-in">Sign in</Link></p>
      </div>
    </div>
  );
}
