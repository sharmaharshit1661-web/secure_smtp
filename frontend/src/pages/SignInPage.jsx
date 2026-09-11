import { SignIn } from '@clerk/clerk-react';
import { Link } from 'react-router-dom';
import Logo from '../components/Logo';
import { clerkAppearance } from '../config/clerkAppearance';

export default function SignInPage() {
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
          <span>Zero-Trust Cryptographic Access Gateway</span>
        </div>
      </div>

      {/* Clerk Prebuilt SignIn Component */}
      {isKeyConfigured ? (
        <SignIn
          routing="path"
          path="/sign-in"
          signUpUrl="/sign-up"
          fallbackRedirectUrl="/"
          withSignUp
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
          <div style={{
            width: '52px',
            height: '52px',
            borderRadius: '12px',
            background: 'rgba(16, 185, 129, 0.06)',
            border: '1px solid rgba(16, 185, 129, 0.2)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            margin: '0 auto 20px',
          }}>
            <img src="/logo.png" alt="Logo" style={{ width: '32px', height: '32px', objectFit: 'contain' }} />
          </div>
          <h2 style={{ fontSize: '20px', fontWeight: 700, color: '#E8E8EC', marginBottom: '8px' }}>
            Clerk Authentication Ready
          </h2>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: '24px' }}>
            The prebuilt Clerk <code>&lt;SignIn /&gt;</code> component and provider have been configured according to the skill. To connect your live Clerk instance, add your publishable key:
          </p>
          <div style={{
            background: '#080809',
            border: '1px solid var(--border)',
            borderRadius: '8px',
            padding: '12px 14px',
            fontSize: '12px',
            fontFamily: 'var(--font-mono)',
            color: 'var(--accent)',
            textAlign: 'left',
            marginBottom: '24px',
            wordBreak: 'break-all',
          }}>
            # In frontend/.env.local<br />
            VITE_CLERK_PUBLISHABLE_KEY=pk_test_...
          </div>
          <div style={{ display: 'flex', gap: '12px', justifyContent: 'center' }}>
            <Link to="/" className="btn btn-primary btn-sm" style={{ padding: '8px 20px' }}>
              Return to Console
            </Link>
          </div>
        </div>
      )}

      {/* Security Footer Notice */}
      <div style={{
        marginTop: '28px',
        fontSize: '11px',
        color: 'var(--text-muted)',
        display: 'flex',
        alignItems: 'center',
        gap: '6px',
        fontFamily: 'var(--font-mono)',
      }}>
        <span>🔒</span>
        <span>End-to-end encrypted session authority via Clerk Identity Protocol</span>
      </div>
    </div>
  );
}
