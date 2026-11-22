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

// Local / evaluation mode provides persistent demo session when Clerk is unconfigured
export function LocalAuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    try {
      const saved = localStorage.getItem('secure_smtp_demo_user');
      return saved ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  });

  const orgId = 'local-dev';

  useEffect(() => {
    if (user) {
      const token = user.role === 'admin' ? 'local-admin-session' : 'local-member-session';
      configureTokenProvider(async () => token);
    } else {
      configureTokenProvider(null);
    }
    return () => configureTokenProvider(null);
  }, [user]);

  const login = (userData) => {
    const u = userData || {
      name: 'SOC Lead Administrator',
      email: 'analyst@corp.io',
      role: 'admin',
      clearance: 'Level 4 SOC Administrator',
    };
    try {
      localStorage.setItem('secure_smtp_demo_user', JSON.stringify(u));
    } catch {}
    setUser(u);
  };

  const logout = () => {
    try {
      localStorage.removeItem('secure_smtp_demo_user');
    } catch {}
    setUser(null);
    configureTokenProvider(null);
  };

  const value = {
    isAuthenticated: Boolean(user),
    user,
    login,
    logout,
    isClerkEnabled: false,
    isLoaded: true,
    orgId: user ? orgId : null,
    offline: false,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
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
