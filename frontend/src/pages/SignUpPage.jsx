import { SignUp } from '@clerk/clerk-react';
import { Link } from 'react-router-dom';
import Logo from '../components/Logo';
import { clerkAppearance } from '../config/clerkAppearance';

export default function SignUpPage() {
  const isKeyConfigured = Boolean(
    import.meta.env.VITE_CLERK_PUBLISHABLE_KEY &&
    !import.meta.env.VITE_CLERK_PUBLISHABLE_KEY.includes('YOUR_KEY')
  );

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'radial-gradient(ellipse at 50% 15%, rgba(16, 185, 129, 0.05) 0%, rgba(5, 5, 5, 0.97) 70%, #050505 100%)',
      padding: '24px 16px',
      position: 'relative',
    }}>
      {/* Brand Header */}
      <div style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        marginBottom: '28px',
        textAlign: 'center',
      }}>
        <Link to="/" style={{ textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
          <Logo size={36} style={{ flexShrink: 0 }} />
          <span style={{ fontFamily: 'var(--font-heading)', fontSize: '20px', fontWeight: 700, color: '#E8E8EC', letterSpacing: '0.01em' }}>
            Secure SMTP
          </span>
          <span className="badge badge-accent" style={{ fontSize: '10px', padding: '2px 8px' }}>v2.0</span>
        </Link>
        <div style={{
          fontSize: '12px',
          color: 'var(--text-secondary)',
          fontFamily: 'var(--font-mono)',
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
        }}>
          <span className="status-dot status-dot-active" />
          <span>Operator Registration & Provisioning</span>
        </div>
      </div>

      {/* Clerk Prebuilt SignUp Component */}
      {isKeyConfigured ? (
        <SignUp
          routing="path"
          path="/sign-up"
          signInUrl="/sign-in"
          fallbackRedirectUrl="/"
          appearance={clerkAppearance}
        />
      ) : (
        <div style={{
          maxWidth: '480px',
          width: '100%',
          background: 'rgba(13, 13, 14, 0.92)',
          backdropFilter: 'blur(20px)',
          border: '1px solid #1F1F23',
          borderRadius: '18px',
          padding: '36px 32px',
          boxShadow: '0 24px 60px rgba(0,0,0,0.7)',
          textAlign: 'center',
        }}>
          <h2 style={{ fontSize: '20px', fontWeight: 700, color: '#E8E8EC', marginBottom: '8px' }}>
            Clerk Configuration Required
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: '24px' }}>
            Add your Clerk publishable key in <code>frontend/.env.local</code> to activate live operator account creation.
          </p>
          <Link to="/sign-in" className="btn btn-primary btn-sm" style={{ padding: '8px 20px' }}>
            Go to Sign In
          </Link>
        </div>
      )}
    </div>
  );
}
