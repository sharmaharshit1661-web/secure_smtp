import React, { useContext, useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useUser, useClerk, useAuth as useClerkAuth } from '@clerk/clerk-react';

import { configureTokenProvider } from '../api/client';

import { AuthContext } from './authState';

// eslint-disable-next-line react-refresh/only-export-components
export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return ctx;
}

// Missing deployment configuration must not unlock a local/demo dashboard.
export function LocalAuthProvider({ children }) {
  return <AuthContext.Provider value={{ isAuthenticated: false, user: null, isClerkEnabled: false, isLoaded: true, login: () => {}, logout: () => {} }}>{children}</AuthContext.Provider>;
}

export function ClerkAuthProvider({ children }) {
  const navigate = useNavigate();
  const { user: clerkUser, isLoaded } = useUser();
  const clerk = useClerk();
  const { getToken, orgId, isLoaded: authLoaded } = useClerkAuth();
  const [tokenReady, setTokenReady] = useState(false);
  useEffect(() => {
    configureTokenProvider(getToken);
    setTokenReady(true);
    return () => configureTokenProvider(null);
  }, [getToken]);

  const user = clerkUser
    ? {
        name: clerkUser.fullName || clerkUser.firstName || clerkUser.primaryEmailAddress?.emailAddress?.split('@')[0] || 'Operator',
        email: clerkUser.primaryEmailAddress?.emailAddress || '',
        role: 'Pilot member',
        clearance: 'Organization access',
      }
    : null;

  const login = () => {
    navigate('/dashboard');
  };

  const logout = async () => {
    try {
      await clerk.signOut();
    } catch (e) {
      console.error('Clerk sign out error', e);
    }
    // Explicitly close the dashboard and return to the landing page
    navigate('/', { replace: true });
  };

  const value = {
    isAuthenticated: Boolean(clerkUser),
    user,
    login,
    logout,
    isClerkEnabled: true,
    isLoaded: isLoaded && authLoaded,
    orgId,
  };

  return <AuthContext.Provider value={value}>{tokenReady ? <React.Fragment key={`${clerkUser?.id || 'signed-out'}:${orgId || 'no-org'}`}>{children}</React.Fragment> : <div className="ui-loading" role="status">Preparing secure sign-in…</div>}</AuthContext.Provider>;
}
