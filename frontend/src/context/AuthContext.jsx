import React, { createContext, useContext, useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useUser, useClerk } from '@clerk/clerk-react';

const AuthContext = createContext(null);

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return ctx;
}

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

  // Sync state across window / tab events
  useEffect(() => {
    const handleStorage = (e) => {
      if (e.key === 'secure_smtp_user') {
        try {
          setUser(e.newValue ? JSON.parse(e.newValue) : null);
        } catch {
          setUser(null);
        }
      }
    };
    window.addEventListener('storage', handleStorage);
    return () => window.removeEventListener('storage', handleStorage);
  }, []);

  const login = (userData) => {
    try {
      localStorage.setItem('secure_smtp_user', JSON.stringify(userData));
    } catch {
      // ignore
    }
    setUser(userData);
    navigate('/dashboard');
  };

  const logout = () => {
    try {
      localStorage.removeItem('secure_smtp_user');
    } catch {
      // ignore
    }
    setUser(null);
    // Explicitly close the dashboard and return to the landing page
    navigate('/', { replace: true });
  };

  const value = {
    isAuthenticated: Boolean(user),
    user,
    login,
    logout,
    isClerkEnabled: false,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function ClerkAuthProvider({ children }) {
  const navigate = useNavigate();
  const { user: clerkUser, isLoaded } = useUser();
  const clerk = useClerk();

  const user = clerkUser
    ? {
        name: clerkUser.fullName || clerkUser.firstName || clerkUser.primaryEmailAddress?.emailAddress?.split('@')[0] || 'Operator',
        email: clerkUser.primaryEmailAddress?.emailAddress || '',
        role: 'Verified Operator',
        clearance: 'Level 4 Cryptographic Clearance',
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
    isLoaded,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
