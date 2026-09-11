import { dark } from '@clerk/themes';

/**
 * Obsidian Stealth Clerk Theme
 * Aligned with the Secure SMTP Obsidian Stealth design system.
 * Canvas #050505 · Surface #0D0D0E · Borders #1F1F23 · Accent Emerald #10B981
 */
export const clerkAppearance = {
  baseTheme: dark,
  variables: {
    colorPrimary: '#10B981',
    colorBackground: '#0D0D0E',
    colorInputBackground: '#080809',
    colorInputText: '#E8E8EC',
    colorText: '#E8E8EC',
    colorTextSecondary: '#7A7A85',
    fontFamily: "'Clash Grotesk', 'Space Grotesk', -apple-system, BlinkMacSystemFont, sans-serif",
    borderRadius: '12px',
    colorNeutral: '#1A1A1E',
    colorDanger: '#EF4444',
    colorSuccess: '#10B981',
  },
  elements: {
    rootBox: {
      width: '100%',
      maxWidth: '440px',
    },
    card: {
      background: 'rgba(13, 13, 14, 0.92)',
      backdropFilter: 'blur(20px)',
      border: '1px solid #1F1F23',
      boxShadow: '0 24px 70px rgba(0, 0, 0, 0.8), 0 0 40px rgba(16, 185, 129, 0.04)',
      borderRadius: '18px',
      padding: '36px 32px',
    },
    headerTitle: {
      fontFamily: "'Exon', 'Clash Grotesk', sans-serif",
      fontSize: '22px',
      fontWeight: '700',
      color: '#E8E8EC',
      letterSpacing: '0.01em',
    },
    headerSubtitle: {
      fontFamily: "'Clash Grotesk', 'Space Grotesk', sans-serif",
      fontSize: '13px',
      color: '#7A7A85',
      marginTop: '4px',
    },
    formButtonPrimary: {
      background: 'linear-gradient(135deg, #10B981 0%, #059669 100%)',
      fontSize: '14px',
      fontWeight: '700',
      borderRadius: '10px',
      color: '#050505',
      boxShadow: '0 4px 18px rgba(16, 185, 129, 0.2)',
      transition: 'all 0.2s cubic-bezier(0.16, 1, 0.3, 1)',
      '&:hover': {
        background: 'linear-gradient(135deg, #34D399 0%, #10B981 100%)',
        boxShadow: '0 6px 24px rgba(16, 185, 129, 0.35)',
        transform: 'translateY(-1px)',
      },
    },
    socialButtonsBlockButton: {
      background: 'rgba(255, 255, 255, 0.02)',
      border: '1px solid #1F1F23',
      borderRadius: '10px',
      color: '#E8E8EC',
      transition: 'all 0.2s ease',
      '&:hover': {
        background: 'rgba(255, 255, 255, 0.04)',
        borderColor: 'rgba(16, 185, 129, 0.3)',
      },
    },
    formFieldInput: {
      background: '#080809',
      border: '1px solid #1F1F23',
      borderRadius: '8px',
      color: '#E8E8EC',
      fontSize: '14px',
      transition: 'border-color 0.2s ease, box-shadow 0.2s ease',
      '&:focus': {
        borderColor: '#10B981',
        boxShadow: '0 0 0 2px rgba(16, 185, 129, 0.12)',
      },
    },
    dividerLine: {
      background: 'rgba(31, 31, 35, 0.8)',
    },
    dividerText: {
      color: '#4A4A52',
      fontSize: '12px',
      textTransform: 'uppercase',
      letterSpacing: '0.05em',
    },
    footerActionLink: {
      color: '#10B981',
      fontWeight: '600',
      '&:hover': {
        color: '#34D399',
        textDecoration: 'underline',
      },
    },
    userButtonAvatarBox: {
      width: '32px',
      height: '32px',
      borderRadius: '8px',
      border: '1px solid #1F1F23',
      boxShadow: '0 0 10px rgba(16, 185, 129, 0.12)',
    },
    userButtonPopoverCard: {
      background: 'rgba(13, 13, 14, 0.96)',
      backdropFilter: 'blur(20px)',
      border: '1px solid #1F1F23',
      borderRadius: '14px',
      boxShadow: '0 16px 48px rgba(0, 0, 0, 0.8)',
    },
  },
};
