import { Link } from 'react-router-dom';
import { SignUp } from '@clerk/clerk-react';
import Logo from '../components/Logo';
import { clerkAppearance } from '../config/clerkAppearance';
import { useAuth } from '../context/AuthContext';

export default function SignUpPage() {
  const { isClerkEnabled } = useAuth();
  return <div className="auth-page"><div className="auth-container">
    <Link to="/" className="auth-back">Back to overview</Link>
    <div className="auth-brand"><Logo size={32} /><span className="auth-brand-name">Secure SMTP</span></div>
    {isClerkEnabled ? <SignUp routing="path" path="/sign-up" signInUrl="/sign-in" fallbackRedirectUrl="/dashboard" appearance={clerkAppearance} /> :
      <div className="auth-card"><h1 className="auth-title">Request account access</h1>
        <p className="auth-subtitle">Local operator accounts are provisioned by your administrator. Contact them for access.</p>
        <Link className="auth-link" to="/sign-in">Return to sign in</Link></div>}
  </div></div>;
}
