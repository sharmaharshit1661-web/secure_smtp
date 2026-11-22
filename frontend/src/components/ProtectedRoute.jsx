import { useEffect, useState } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { OrganizationSwitcher, UserButton } from '@clerk/clerk-react';
import { useAuth } from '../context/AuthContext';
import { PilotContext } from '../context/PilotContext';
import { getIdentity } from '../api/client';

function PilotAccess({ orgId, children }) {
  const { offline, logout } = useAuth();
  const [access, setAccess] = useState('checking');
  const [verifiedIdentity, setVerifiedIdentity] = useState(null);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    if (!orgId) return;
    let active = true;
    getIdentity().then(identity => {
      if (!active) return;
      setVerifiedIdentity(identity);
      setAccess((offline || identity.org_id === orgId) ? 'allowed' : 'membership');
    }).catch(error => {
      if (active) setAccess(error.status === 403 ? 'membership' : 'unavailable');
    });
    return () => { active = false; };
  }, [orgId, attempt, offline]);

  if (orgId && access === 'allowed') return <PilotContext.Provider value={verifiedIdentity}>{children}</PilotContext.Provider>;
  if (orgId && access === 'checking') return <p className="ui-loading" role="status">Checking pilot access…</p>;
  const unavailable = access === 'unavailable';
  return <main className="auth-page"><section className="auth-card">
    {offline ? <button className="btn btn-outline" onClick={logout}>Sign out</button> : <UserButton />}
    <h1 className="auth-title">{unavailable ? 'Access check unavailable' : offline ? 'Account access required' : 'Choose your pilot organization'}</h1>
    <p className="auth-subtitle">{unavailable ? 'We could not verify your session. Try again or sign in with your pilot account.' : offline ? 'Ask your local administrator to assign the analyst or administrator role.' : 'Select the organization that invited you. If it is missing, open your invitation using the same email address.'}</p>
    {!offline && <OrganizationSwitcher hidePersonal />}
    {orgId && <button className="btn btn-outline" onClick={() => { setAccess('checking'); setAttempt(n => n + 1); }}>Check access again</button>}
  </section></main>;
}

export default function ProtectedRoute({ children }) {
  const { isAuthenticated, isLoaded, orgId } = useAuth();
  const location = useLocation();
  if (!isLoaded) return <p className="ui-loading" role="status">Preparing sign-in…</p>;
  if (!isAuthenticated) return <Navigate to="/sign-in" state={{ from: location }} replace />;
  return <PilotAccess key={orgId || 'choose'} orgId={orgId}>{children}</PilotAccess>;
}
