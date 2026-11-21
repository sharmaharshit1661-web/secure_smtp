import { createContext, useContext, useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useUser, useClerk, useAuth as useClerkAuth } from '@clerk/clerk-react';
import { authRequest, setTokenProvider } from '../api/client';

const AuthContext = createContext(null);
// eslint-disable-next-line react-refresh/only-export-components
export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within an AuthProvider');
  return context;
}

export function LocalAuthProvider({ children }) {
  const navigate = useNavigate();
  const [user, setUser] = useState(null);
  const [isLoaded, setIsLoaded] = useState(false);
  useEffect(() => {
    let active = true;
    // Old demo objects never establish a session.
    localStorage.removeItem('secure_smtp_user');
    authRequest('/me').then(data => { if (active) setUser(data); })
      .catch(() => { if (active) setUser(null); })
      .finally(() => { if (active) setIsLoaded(true); });
    return () => { active = false; };
  }, []);
  async function login(credentials) {
    const verified = await authRequest('/login', credentials);
    setUser(verified);
    navigate('/dashboard');
  }
  async function logout() {
    await authRequest('/logout', {});
    setUser(null);
    navigate('/', { replace: true });
  }
  return <AuthContext.Provider value={{ user, isLoaded, isAuthenticated: Boolean(user), login, logout, isClerkEnabled: false }}>{children}</AuthContext.Provider>;
}

export function ClerkAuthProvider({ children }) {
  const navigate = useNavigate();
  const { user, isLoaded } = useUser();
  const { getToken } = useClerkAuth();
  const clerk = useClerk();
  const [ready, setReady] = useState(false);
  useEffect(() => {
    setTokenProvider(getToken);
    setReady(true);
    return () => setTokenProvider(null);
  }, [getToken]);
  async function logout() {
    await clerk.signOut();
    navigate('/', { replace: true });
  }
  const profile = user ? {
    name: user.fullName || user.firstName || 'Operator',
    email: user.primaryEmailAddress?.emailAddress || '',
    role: 'Authenticated operator',
  } : null;
  return <AuthContext.Provider value={{ user: profile, isLoaded: isLoaded && ready, isAuthenticated: Boolean(user), logout, isClerkEnabled: true }}>{children}</AuthContext.Provider>;
}
