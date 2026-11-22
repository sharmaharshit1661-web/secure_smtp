import React from 'react';

export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('ErrorBoundary caught an error:', error, errorInfo);
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null });
    window.location.href = '/';
  };

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          minHeight: '100vh',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          background: 'var(--bg-canvas)',
          color: 'var(--text-primary)',
          padding: '24px',
          fontFamily: 'var(--font-sans, system-ui, sans-serif)',
        }}>
          <div style={{
            maxWidth: '520px',
            width: '100%',
            background: 'var(--bg-surface)',
            border: '1px solid var(--border)',
            borderRadius: '16px',
            padding: '36px 32px',
            textAlign: 'center',
            boxShadow: 'var(--shadow-lg)',
          }}>
            <div style={{
              width: '48px',
              height: '48px',
              borderRadius: '12px',
              background: 'rgba(239, 68, 68, 0.1)',
              border: '1px solid rgba(239, 68, 68, 0.3)',
              color: 'var(--sev-critical)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              margin: '0 auto 20px',
              fontSize: '20px',
            }}>
              ⚠
            </div>
            <h2 style={{ fontSize: '20px', fontWeight: 700, marginBottom: '8px' }}>
              Forensic Console Interrupted
            </h2>
            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: '20px' }}>
              An unexpected render exception was safely trapped by the security boundary.
            </p>
            {this.state.error?.message && (
              <div style={{
                background: 'var(--bg-canvas)',
                border: '1px solid var(--border)',
                borderRadius: '8px',
                padding: '12px',
                fontFamily: 'monospace',
                fontSize: '11px',
                color: 'var(--sev-critical)',
                textAlign: 'left',
                marginBottom: '24px',
                overflowX: 'auto',
              }}>
                {this.state.error.message}
              </div>
            )}
            <button
              onClick={this.handleReset}
              style={{
                background: 'var(--action-bg)',
                color: 'var(--action-text)',
                fontWeight: 600,
                fontSize: '13px',
                padding: '10px 24px',
                borderRadius: '8px',
                border: 'none',
                cursor: 'pointer',
                transition: 'background 150ms ease',
              }}
            >
              Reload Secure SMTP
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
