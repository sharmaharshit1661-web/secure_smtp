import { useEffect, useState } from 'react';
import Keycloak from 'keycloak-js';
import { AuthContext } from './authState';
import { configureTokenProvider } from '../api/client';

let initialized;
function initialize() {
  if (!initialized) {
    const client = new Keycloak({url: location.origin + '/id', realm: 'pilot', clientId: 'secure-smtp'});
    initialized = client.init({
      onLoad: 'login-required', pkceMethod: 'S256', checkLoginIframe: false,
      redirectUri: location.origin + '/dashboard',
    }).then(() => client);
  }
  return initialized;
}

export default function OfflineProvider({ children }) {
  const [client, setClient] = useState(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    let active = true;
    initialize().then(kc => {
      if (!active) return;
      configureTokenProvider(async () => {
        try {
          await kc.updateToken(30);
          return kc.token;
        } catch {
          setFailed(true);
          throw new Error('Local session expired. Sign in again.');
        }
      });
      setClient(kc);
    }).catch(() => { if (active) setFailed(true); });
    return () => { active = false; configureTokenProvider(null); };
  }, []);
  if (failed) return <main className="auth-page"><section className="auth-card"><h1>Local sign-in unavailable</h1><button onClick={() => location.assign('/dashboard')}>Try again</button></section></main>;
  if (!client) return <p role="status">Opening local sign-in…</p>;
  return <AuthContext.Provider value={{ offline: true, isAuthenticated: client.authenticated,
    isLoaded: true, isClerkEnabled: false, orgId: 'pilot', user: { name: client.tokenParsed.preferred_username },
    logout: () => client.logout({redirectUri: location.origin + '/'}) }}>{children}</AuthContext.Provider>;
}
