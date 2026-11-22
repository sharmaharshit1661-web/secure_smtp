import { dark } from '@clerk/themes';

/** Shared authentication styling, including Clerk's dialogs and account popover. */
const elements = {
  rootBox: { width: '100%', maxWidth: '480px' },
  card: { background: 'var(--bg-elevated)', boxShadow: 'none', borderRadius: '6px', padding: '36px 32px' },
  headerTitle: { fontFamily: "'Space Grotesk', sans-serif", fontSize: '30px', fontWeight: '500', color: 'var(--text-primary)', letterSpacing: '-0.03em' },
  headerSubtitle: { color: 'var(--text-secondary)', fontSize: '14px' },
  formButtonPrimary: { background: 'var(--action-bg)', color: 'var(--action-text)', borderRadius: '4px', minHeight: '48px', boxShadow: 'none', '&:hover': { background: 'var(--action-hover)' } },
  socialButtonsBlockButton: { background: 'var(--bg-input)', border: '1px solid var(--border-strong)', color: 'var(--text-primary)', borderRadius: '4px' },
  formFieldInput: { background: 'var(--bg-input)', border: '1px solid var(--border-strong)', color: 'var(--text-primary)', borderRadius: '4px', minHeight: '48px', fontSize: '16px' },
  dividerLine: { background: 'var(--border-strong)' }, dividerText: { color: 'var(--text-secondary)' },
  footerActionLink: { color: 'var(--accent)', fontWeight: '600' },
  userButtonAvatarBox: { width: '32px', height: '32px', borderRadius: '6px' },
  userButtonPopoverCard: { background: 'var(--bg-canvas)', border: '1px solid var(--border)', borderRadius: '6px', boxShadow: 'var(--shadow-lg)' },
};
const appearances = Object.fromEntries(['light', 'dark'].map(theme => {
  const isDark = theme === 'dark';
  return [theme, {
    baseTheme: isDark ? dark : undefined,
    variables: {
      colorPrimary: isDark ? '#bcf56a' : '#13251f',
      colorPrimaryForeground: isDark ? '#13251f' : '#f5f7f1',
      colorBackground: isDark ? '#202f25' : '#e9ede3',
      colorInputBackground: isDark ? '#131e18' : '#f9faf6',
      colorInputText: isDark ? '#edf2e9' : '#13251f',
      colorText: isDark ? '#edf2e9' : '#13251f',
      colorTextSecondary: isDark ? '#b9c6b7' : '#5e6c64',
      colorNeutral: isDark ? '#edf2e9' : '#13251f',
      colorDanger: isDark ? '#ff9b91' : '#b42318',
      colorSuccess: isDark ? '#b4df8b' : '#386c35',
      fontFamily: "'Inter', sans-serif", borderRadius: '6px',
    },
    elements,
  }];
}));

export function getClerkAppearance(theme) {
  return appearances[theme] || appearances.light;
}
