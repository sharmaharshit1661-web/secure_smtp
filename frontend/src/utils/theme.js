export const THEME_KEY = 'secure_smtp_theme';

export function resolveTheme(preference, systemDark) {
  return preference === 'light' || preference === 'dark'
    ? preference
    : systemDark ? 'dark' : 'light';
}

export function readThemePreference(storage) {
  try {
    const value = storage.getItem(THEME_KEY);
    return value === 'light' || value === 'dark' ? value : null;
  } catch {
    return null;
  }
}

export function saveThemePreference(storage, theme) {
  try { storage.setItem(THEME_KEY, theme); } catch { /* Private browsing can disable storage. */ }
}

export function applyTheme(theme, doc) {
  doc.documentElement.dataset.theme = theme;
  doc.documentElement.style.colorScheme = theme;
  doc.querySelector('meta[name="theme-color"]')?.setAttribute('content', theme === 'dark' ? '#101914' : '#f5f7f1');
}
