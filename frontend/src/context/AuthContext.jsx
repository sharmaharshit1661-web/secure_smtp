import React, { useContext, useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useUser, useClerk, useAuth as useClerkAuth } from '@clerk/react';

import { configureTokenProvider, loginUser, registerUser, demoLogin } from '../api/client';

import { AuthContext } from './authState';

// eslint-disable-next-line react-refresh/only-export-components
export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return ctx;
}

// Native MongoDB authentication provider when Clerk is unconfigured or in native mode
export function LocalAuthProvider({ children }) {
  const navigate = useNavigate();
  const [user, setUser] = useState(() => {
    try {
      const saved = localStorage.getItem('secure_smtp_user');
      return saved ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  });

  useEffect(() => {
    try {
      const token = localStorage.getItem('secure_smtp_token');
      if (token && user) {
        configureTokenProvider(async () => token);
      } else {
        configureTokenProvider(null);
      }
    } catch {
      configureTokenProvider(null);
    }
    return () => configureTokenProvider(null);
  }, [user]);

  const login = async (email, password) => {
    const data = await loginUser(email, password);
    try {
      localStorage.setItem('secure_smtp_token', data.token);
      localStorage.setItem('secure_smtp_user', JSON.stringify(data.user));
    } catch {}
    configureTokenProvider(async () => data.token);
    setUser(data.user);
    navigate('/dashboard');
    return data.user;
  };

  const register = async ({ name, email, password, role }) => {
    const data = await registerUser({ name, email, password, role });
    try {
      localStorage.setItem('secure_smtp_token', data.token);
      localStorage.setItem('secure_smtp_user', JSON.stringify(data.user));
    } catch {}
    configureTokenProvider(async () => data.token);
    setUser(data.user);
    navigate('/dashboard');
    return data.user;
  };

  const loginDemo = async () => {
    try {
      const data = await demoLogin();
      localStorage.setItem('secure_smtp_token', data.token);
      localStorage.setItem('secure_smtp_user', JSON.stringify(data.user));
      configureTokenProvider(async () => data.token);
      setUser(data.user);
      navigate('/dashboard');
      return data.user;
    } catch {
      // Fallback demo user if network error during demo
      const fallback = {
        name: 'SOC Lead Administrator',
        email: 'analyst@corp.io',
        role: 'admin',
        org_id: 'pilot',
      };
      localStorage.setItem('secure_smtp_token', 'local-admin-session');
      localStorage.setItem('secure_smtp_user', JSON.stringify(fallback));
      configureTokenProvider(async () => 'local-admin-session');
      setUser(fallback);
      navigate('/dashboard');
      return fallback;
    }
  };

  const logout = () => {
    try {
      localStorage.removeItem('secure_smtp_token');
      localStorage.removeItem('secure_smtp_user');
    } catch {}
    configureTokenProvider(null);
    setUser(null);
    navigate('/', { replace: true });
  };

  const value = {
    isAuthenticated: Boolean(user),
    user,
    orgId: user?.org_id || 'pilot',
    isClerkEnabled: false,
    isLoaded: true,
    login,
    register,
    loginDemo,
    logout,
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

  // Native user fallback/state inside Clerk provider
  const [nativeUser, setNativeUser] = useState(() => {
    try {
      const saved = localStorage.getItem('secure_smtp_user');
      return saved ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  });

  useEffect(() => {
    const nativeToken = localStorage.getItem('secure_smtp_token');
    if (nativeToken && nativeUser) {
      configureTokenProvider(async () => nativeToken);
      setTokenReady(true);
      return () => configureTokenProvider(null);
    }

    if (getToken) {
      configureTokenProvider(getToken);
      setTokenReady(true);
      return () => configureTokenProvider(null);
    }

    setTokenReady(true);
    return () => configureTokenProvider(null);
  }, [getToken, nativeUser]);

  const clerkMappedUser = clerkUser
    ? {
        name: clerkUser.fullName || clerkUser.firstName || clerkUser.primaryEmailAddress?.emailAddress?.split('@')[0] || 'Operator',
        email: clerkUser.primaryEmailAddress?.emailAddress || '',
        role: 'Pilot member',
        clearance: 'Organization access',
        org_id: orgId || 'pilot',
      }
    : null;

  const effectiveUser = nativeUser || clerkMappedUser;

  const login = async (email, password) => {
    const data = await loginUser(email, password);
    try {
      localStorage.setItem('secure_smtp_token', data.token);
      localStorage.setItem('secure_smtp_user', JSON.stringify(data.user));
    } catch {}
    configureTokenProvider(async () => data.token);
    setNativeUser(data.user);
    navigate('/dashboard');
    return data.user;
  };

  const register = async ({ name, email, password, role }) => {
    const data = await registerUser({ name, email, password, role });
    try {
      localStorage.setItem('secure_smtp_token', data.token);
      localStorage.setItem('secure_smtp_user', JSON.stringify(data.user));
    } catch {}
    configureTokenProvider(async () => data.token);
    setNativeUser(data.user);
    navigate('/dashboard');
    return data.user;
  };

  const loginDemo = async () => {
    try {
      const data = await demoLogin();
      localStorage.setItem('secure_smtp_token', data.token);
      localStorage.setItem('secure_smtp_user', JSON.stringify(data.user));
      configureTokenProvider(async () => data.token);
      setNativeUser(data.user);
      navigate('/dashboard');
      return data.user;
    } catch {
      const fallback = {
        name: 'SOC Lead Administrator',
        email: 'analyst@corp.io',
        role: 'admin',
        org_id: 'pilot',
      };
      localStorage.setItem('secure_smtp_token', 'local-admin-session');
      localStorage.setItem('secure_smtp_user', JSON.stringify(fallback));
      configureTokenProvider(async () => 'local-admin-session');
      setNativeUser(fallback);
      navigate('/dashboard');
      return fallback;
    }
  };

  const logout = async () => {
    try {
      localStorage.removeItem('secure_smtp_token');
      localStorage.removeItem('secure_smtp_user');
    } catch {}
    setNativeUser(null);
    configureTokenProvider(null);
    if (clerk && clerkUser) {
      try {
        await clerk.signOut();
      } catch (e) {
        console.error('Clerk sign out error', e);
      }
    }
    navigate('/', { replace: true });
  };

  const value = {
    isAuthenticated: Boolean(effectiveUser),
    user: effectiveUser,
    login,
    register,
    loginDemo,
    logout,
    isClerkEnabled: true,
    isLoaded: isLoaded && authLoaded,
    orgId: effectiveUser?.org_id || orgId || 'pilot',
    offline: false,
  };

  return <AuthContext.Provider value={value}>{tokenReady ? <React.Fragment key={`${effectiveUser?.id || clerkUser?.id || 'signed-out'}:${orgId || 'no-org'}`}>{children}</React.Fragment> : <div className="ui-loading" role="status">Preparing secure sign-in…</div>}</AuthContext.Provider>;
}
