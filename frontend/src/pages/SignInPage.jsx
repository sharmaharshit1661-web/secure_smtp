import { Link, Navigate } from 'react-router-dom';
import { SignIn } from '@clerk/react';
import ThemeToggle from '../components/ThemeToggle';
import Logo from '../components/Logo';
import { useAuth } from '../context/AuthContext';

export default function SignInPage() {
  const { isClerkEnabled, isAuthenticated, offline } = useAuth();
  if (offline || isAuthenticated) return <Navigate to="/dashboard" replace />;
  return <main className="auth-page"><div className="auth-container">
    <div className="auth-theme-control"><ThemeToggle /></div>
    <Link to="/" className="auth-back">Back to overview</Link>
    <div className="auth-brand"><Logo size={32} /><span className="auth-brand-name">Secure SMTP</span></div>
    <h1 className="sr-only">Sign in to Secure SMTP</h1>
    {isClerkEnabled ? <SignIn routing="path" path="/sign-in" signUpUrl="/sign-up" fallbackRedirectUrl="/dashboard" />
      : <section className="auth-card"><h1 className="auth-title">Sign-in is not configured</h1>
        <p className="auth-subtitle">Your administrator must configure the Clerk application before you can sign in.</p></section>}
    <p className="auth-subtitle">New here? <Link to="/sign-up">Create an account</Link></p>
  </div></main>;
}
