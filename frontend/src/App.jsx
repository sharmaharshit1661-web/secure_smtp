import { BrowserRouter, Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import { ClerkProvider } from '@clerk/clerk-react';
import Layout from './components/Layout';
import ProtectedRoute from './components/ProtectedRoute';
import { ClerkAuthProvider, LocalAuthProvider } from './context/AuthContext';
import FleetOverview from './pages/FleetOverview';
import SessionExplorer from './pages/SessionExplorer';
import LiveIngest from './pages/LiveIngest';
import ClientDispatcher from './pages/ClientDispatcher';
import RulesCompliance from './pages/RulesCompliance';
import AiSecurity from './pages/AiSecurity';
import SignInPage from './pages/SignInPage';
import SignUpPage from './pages/SignUpPage';
import LandingPage from './pages/LandingPage';
import { clerkAppearance } from './config/clerkAppearance';

const PUBLISHABLE_KEY = import.meta.env.VITE_CLERK_PUBLISHABLE_KEY;
const isClerkEnabled = Boolean(PUBLISHABLE_KEY && !PUBLISHABLE_KEY.includes('YOUR_KEY'));

function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<LandingPage />} />
      <Route path="/sign-in/*" element={<SignInPage />} />
      <Route path="/sign-up/*" element={<SignUpPage />} />
      <Route
        path="/dashboard"
        element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }
      >
        <Route index element={<FleetOverview />} />
        <Route path="sessions" element={<SessionExplorer />} />
        <Route path="sessions/:hostId" element={<SessionExplorer />} />
        <Route path="ingest" element={<LiveIngest />} />
        <Route path="client" element={<ClientDispatcher />} />
        <Route path="rules" element={<RulesCompliance />} />
        <Route path="ai-security" element={<AiSecurity />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

function AuthProviderWrapper() {
  const navigate = useNavigate();

  if (!isClerkEnabled) {
    return (
      <LocalAuthProvider>
        <AppRoutes />
      </LocalAuthProvider>
    );
  }

  return (
    <ClerkProvider
      publishableKey={PUBLISHABLE_KEY}
      routerPush={(to) => navigate(to)}
      routerReplace={(to) => navigate(to, { replace: true })}
      appearance={clerkAppearance}
    >
      <ClerkAuthProvider>
        <AppRoutes />
      </ClerkAuthProvider>
    </ClerkProvider>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProviderWrapper />
    </BrowserRouter>
  );
}
