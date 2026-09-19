import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function ProtectedRoute({ children }) {
  const { isAuthenticated, isClerkEnabled, isLoaded } = useAuth();
  const location = useLocation();

  // If Clerk is enabled, wait until Clerk finishes initializing
  if (isClerkEnabled && isLoaded === false) {
    return (
      <div style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: '#050505',
        color: '#E8E8EC',
        fontFamily: 'var(--font-mono)',
        fontSize: '13px',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span className="auth-spinner" style={{ borderColor: 'rgba(255,255,255,0.2)', borderTopColor: '#10B981' }} />
          Verifying security clearance…
        </div>
      </div>
    );
  }

  // If not authenticated, lock out and redirect to sign-in
  if (!isAuthenticated) {
    return <Navigate to="/sign-in" state={{ from: location }} replace />;
  }

  return children;
}
