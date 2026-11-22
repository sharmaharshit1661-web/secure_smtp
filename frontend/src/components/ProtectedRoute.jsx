import { useEffect, useState } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { OrganizationSwitcher, UserButton } from '@clerk/react';
import { useAuth } from '../context/AuthContext';
import { PilotContext } from '../context/PilotContext';
import { getIdentity } from '../api/client';

function PilotAccess({ orgId, children }) {
  const { offline, logout, isClerkEnabled } = useAuth();
  const [access, setAccess] = useState('checking');
  const [verifiedIdentity, setVerifiedIdentity] = useState(null);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let active = true;
    getIdentity().then(identity => {
      if (!active) return;
      setVerifiedIdentity(identity);
      setAccess('allowed');
    }).catch(error => {
      if (active) {
        setVerifiedIdentity(null);
        setAccess(error.status === 403 ? 'membership' : 'unavailable');
      }
    });
    return () => { active = false; };
  }, [orgId, attempt, offline, isClerkEnabled]);

  if (access === 'allowed') return <PilotContext.Provider value={verifiedIdentity}>{children}</PilotContext.Provider>;
  if (access === 'checking') return <p className="ui-loading" role="status">Checking account access…</p>;
  const unavailable = access === 'unavailable';
  return <main className="auth-page"><section className="auth-card">
    {!isClerkEnabled || offline ? <button className="btn btn-outline" onClick={logout}>Sign out</button> : <UserButton />}
    <h1 className="auth-title">{unavailable ? 'Access check unavailable' : 'Account access required'}</h1>
    <p className="auth-subtitle">{unavailable ? 'We could not verify your session. Try again or sign in again.' : offline ? 'Ask your local administrator to assign the analyst or administrator role.' : 'Switch to your personal account to use your private workspace, or choose an organization you are authorized to access.'}</p>
    {isClerkEnabled && !offline && <OrganizationSwitcher />}
    {<button className="btn btn-outline" onClick={() => { setAccess('checking'); setAttempt(n => n + 1); }}>Check access again</button>}
  </section></main>;
}

export default function ProtectedRoute({ children }) {
  const { isAuthenticated, isLoaded, orgId } = useAuth();
  const location = useLocation();
  if (!isLoaded) return <p className="ui-loading" role="status">Preparing sign-in…</p>;
  if (!isAuthenticated) return <Navigate to="/sign-in" state={{ from: location }} replace />;
  return <PilotAccess key={orgId || 'choose'} orgId={orgId}>{children}</PilotAccess>;
}
