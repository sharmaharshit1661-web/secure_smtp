import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import ThemeToggle from '../components/ThemeToggle';
import Icon from '../components/Icon';
import './LandingPage.css';

const Arrow = () => <span aria-hidden="true">↗</span>;
const standards = [
  ['NIST SP 800-52r2', 'TLS implementation guidelines'],
  ['PCI-DSS v4.0', 'Payment card data security'],
  ['RFC 8996', 'Deprecating TLS 1.0 and 1.1'],
  ['RFC 8314', 'Cleartext considered obsolete'],
  ['RFC 7525', 'TLS best current practice'],
  ['X.509 v3', 'Certificate chain validation'],
];

function DefenseNetwork() {
  return (
    <div className="defense-network" role="img" aria-label="Illustrative mail defense network showing TLS inspection and a detected weak cipher">
      <div className="defense-canvas" aria-hidden="true">
        <div className="defense-label">SECURE SMTP / DEFENSE NETWORK</div>
        <div className="defense-status"><i /> DEMO</div>
        <div className="defense-grid" />
        {[420, 330, 240, 150].map((size) => <img key={size} className={`defense-radius radius-${size}`} src={`/figma/radius-${size}.svg`} alt="" width={size} height={size} />)}
        <div className="defense-core"><Icon name="shield" size={52} /></div>
        {[[167, 168], [425, 197], [199, 412], [451, 367], [91, 309]].map(([x, y]) => <img key={x} className="defense-signal" src="/figma/signal.svg" alt="" width="9" height="9" style={{ left: x, top: y }} />)}
        <div className="defense-notice"><i /><div><strong>Weak cipher detected</strong><p>mail.example / TLS 1.0</p></div></div>
        <div className="defense-bottom"><span>VISIBILITY AT EVERY HANDSHAKE</span><Arrow /></div>
      </div>
    </div>
  );
}

function WorkspacePreview() {
  return <div className="workspace-preview">
    <aside><span className="preview-brand">Secure SMTP</span><span className="preview-active">Fleet overview</span><span>Session explorer</span><span>Live ingest</span><span>Compliance</span><span>AI security</span><div className="preview-workspace"><small>WORKSPACE</small><span>Example / Mail infrastructure</span></div></aside>
    <div className="preview-main">
      <div className="preview-heading"><div><h3>Security overview</h3><p>Your mail infrastructure, in one view.</p></div><small>ILLUSTRATIVE DATA</small></div>
      <div className="preview-metrics">{[['Average risk', '38', '/ 100', 'Prioritize exposed hosts'], ['Open findings', '7', '', '2 require attention'], ['Mail sessions', '14', '', 'Across 3 monitored hosts']].map(([title, value, unit, sub]) => <div key={title}><span>{title}</span><strong>{value} <small>{unit}</small></strong><p>{sub}</p></div>)}</div>
      <h4>Priority findings</h4>
      <div className="preview-table-wrap"><table><thead><tr><th>Severity</th><th>Finding</th><th>Host</th><th>Status</th></tr></thead><tbody>
        <tr><td><span className="preview-badge high">High</span></td><td>Legacy TLS version negotiated</td><td>mail.example</td><td>Needs review</td></tr>
        <tr><td><span className="preview-badge medium">Medium</span></td><td>Weak cipher suite selected</td><td>mx.example</td><td>Investigating</td></tr>
        <tr><td><span className="preview-badge low">Low</span></td><td>Certificate expires soon</td><td>imap.example</td><td>Triaged</td></tr>
      </tbody></table></div>
    </div>
  </div>;
}

export default function LandingPage() {
  const { isAuthenticated, logout } = useAuth();
  const [menuOpen, setMenuOpen] = useState(false);
  useEffect(() => {
    if (!menuOpen) return;
    const closeOnEscape = (event) => {
      if (event.key === 'Escape') {
        setMenuOpen(false);
        document.querySelector('.cipher-menu-toggle')?.focus();
      }
    };
    window.addEventListener('keydown', closeOnEscape);
    return () => window.removeEventListener('keydown', closeOnEscape);
  }, [menuOpen]);
  const consolePath = isAuthenticated ? '/dashboard' : '/sign-in';
  const navLinks = [['Home', '#home'], ['Platform', '#platform'], ['Capabilities', '#capabilities'], ['Compliance', '#compliance']];
  return <div className="cipher-site" id="home">
    <a href="#main-content" className="skip-link">Skip to content</a>
    <header className="cipher-header"><div className="cipher-container cipher-navigation">
      <Link to="/" className="cipher-wordmark" aria-label="Secure SMTP home">secure<span>smtp</span></Link>
      <nav className="cipher-desktop-nav" aria-label="Main navigation">{navLinks.map(([label, href], i) => <a key={label} href={href} className={i === 0 ? 'current' : ''}>{label}</a>)}</nav>
      <Link to={consolePath} className="cipher-button nav-console">{isAuthenticated ? 'Open console' : 'Sign in to console'}<Arrow /></Link>
      <ThemeToggle />
      <button type="button" className="cipher-menu-toggle" aria-expanded={menuOpen} aria-controls="cipher-mobile-nav" aria-label={menuOpen ? 'Close navigation' : 'Open navigation'} onClick={() => setMenuOpen(!menuOpen)}><Icon name={menuOpen ? 'x' : 'menu'} size={22} /></button>
    </div>{menuOpen && <nav id="cipher-mobile-nav" className="cipher-mobile-nav" aria-label="Mobile navigation">{navLinks.map(([label, href]) => <a key={label} href={href} onClick={() => setMenuOpen(false)}>{label}</a>)}<Link to={consolePath}>Open console <Arrow /></Link></nav>}</header>
    <main id="main-content" tabIndex={-1}>
      <section className="cipher-container cipher-hero">
        <div className="cipher-hero-grid"><div className="cipher-hero-copy">

          <h1>Email security<br />without the<br />blind spots.</h1>
          <p className="cipher-lead">Find weak encryption, inspect certificates, and understand your mail security risks.</p>
          <div className="cipher-actions"><Link to={isAuthenticated ? consolePath : "/sign-up"} className="cipher-button">{isAuthenticated ? "Open console" : "Create an account"}<Arrow /></Link><a href="#platform" className="cipher-text-link">See the platform <span aria-hidden="true">→</span></a></div>

        </div><DefenseNetwork /></div>
      </section>
      <section className="cipher-container cipher-section" id="capabilities">
        <div className="cipher-section-heading"><h2>From traffic to action.</h2></div>
        <div className="cipher-capabilities compact-capabilities">{[
          ['Inspect sessions', 'See TLS settings and certificate evidence.', '/dashboard/sessions'],
          ['Find risks', 'Spot weak encryption and downgrade attempts.', '/dashboard/ai-security'],
          ['Test and improve', 'Compare scenarios and review suggested fixes.', '/dashboard/client'],
        ].map(([title, body, to]) => <article key={title}><h3>{title}</h3><p>{body}</p><Link to={to}>Explore <Arrow /></Link></article>)}</div>
      </section>
      <section className="cipher-platform" id="platform"><div className="cipher-container">
        <div className="cipher-section-heading"><h2>Your security, in one view.</h2></div>
        <WorkspacePreview /><div className="preview-caption"><span>ILLUSTRATIVE WORKSPACE · SAMPLE DATA</span><Link to={consolePath}>Explore the platform <Arrow /></Link></div>
      </div></section>
      <section className="cipher-container compact-standards" id="compliance"><details className="cipher-standards"><summary>Standards and validation frameworks</summary><dl>{standards.map(([code, description]) => <div key={code}><dt>{code}</dt><dd>{description}</dd></div>)}</dl><Link className="cipher-text-link" to="/dashboard/rules">Explore compliance rules <Arrow /></Link></details></section>
      <section className="cipher-cta compact-cta"><div className="cipher-container"><h2>Start with your traffic.</h2><Link to="/dashboard/ingest" className="cipher-button">Analyze a capture <Arrow /></Link></div></section>
    </main>
    <footer className="cipher-footer compact-footer"><div className="cipher-container"><Link to="/" className="cipher-wordmark">secure<span>smtp</span></Link><nav aria-label="Footer"><Link to="/dashboard/rules">Compliance</Link>{isAuthenticated ? <button onClick={logout}>Sign out</button> : <Link to="/sign-in">Sign in</Link>}<a href="https://github.com/sharmaharshit1661-web" target="_blank" rel="noreferrer">GitHub <Arrow /></a></nav><small>© {new Date().getFullYear()} Secure SMTP</small></div></footer>
  </div>;
}
