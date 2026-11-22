import { useEffect, useState } from 'react';
import { THEME_KEY, applyTheme, readThemePreference, resolveTheme, saveThemePreference } from '../utils/theme';

import { ThemeContext } from '../hooks/useTheme';
const systemQuery = '(prefers-color-scheme: dark)';
// Accessing the storage property itself can throw in restricted browser contexts.
function storage() {
  try { return window.localStorage; } catch { return null; }
}

export function ThemeProvider({ children }) {
  const [preference, setPreference] = useState(() => readThemePreference(storage()));
  const [systemDark, setSystemDark] = useState(() => window.matchMedia(systemQuery).matches);
  const theme = resolveTheme(preference, systemDark);

  useEffect(() => {
    const query = window.matchMedia(systemQuery);
    const onSystemChange = event => setSystemDark(event.matches);
    const onStorageChange = event => {
      if (event.key === THEME_KEY || event.key === null) setPreference(readThemePreference(storage()));
    };
    query.addEventListener('change', onSystemChange);
    window.addEventListener('storage', onStorageChange);
    return () => {
      query.removeEventListener('change', onSystemChange);
      window.removeEventListener('storage', onStorageChange);
    };
  }, []);

  useEffect(() => { applyTheme(theme, document); }, [theme]);

  function toggleTheme() {
    const next = theme === 'dark' ? 'light' : 'dark';
    applyTheme(next, document);
    setPreference(next);
    saveThemePreference(storage(), next);
  }

  return <ThemeContext.Provider value={{ theme, toggleTheme }}>{children}</ThemeContext.Provider>;
}
