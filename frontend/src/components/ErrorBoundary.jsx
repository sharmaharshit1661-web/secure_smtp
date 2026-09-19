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
          background: '#050505',
          color: '#E8E8EC',
          padding: '24px',
          fontFamily: 'var(--font-sans, system-ui, sans-serif)',
        }}>
          <div style={{
            maxWidth: '520px',
            width: '100%',
            background: '#0D0D0E',
            border: '1px solid #1F1F23',
            borderRadius: '16px',
            padding: '36px 32px',
            textAlign: 'center',
            boxShadow: '0 24px 60px rgba(0, 0, 0, 0.7)',
          }}>
            <div style={{
              width: '48px',
              height: '48px',
              borderRadius: '12px',
              background: 'rgba(239, 68, 68, 0.1)',
              border: '1px solid rgba(239, 68, 68, 0.3)',
              color: '#EF4444',
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
            <p style={{ fontSize: '13px', color: '#7A7A85', lineHeight: 1.6, marginBottom: '20px' }}>
              An unexpected render exception was safely trapped by the security boundary.
            </p>
            {this.state.error?.message && (
              <div style={{
                background: '#080809',
                border: '1px solid #1F1F23',
                borderRadius: '8px',
                padding: '12px',
                fontFamily: 'monospace',
                fontSize: '11px',
                color: '#EF4444',
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
                background: '#10B981',
                color: '#050505',
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
