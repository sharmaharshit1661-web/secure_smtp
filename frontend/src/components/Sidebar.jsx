import { useState, useEffect } from 'react';
import { NavLink } from 'react-router-dom';
import Icon from './Icon';
import Logo from './Logo';

const NAV_ITEMS = [
  { to: '/', label: 'Fleet Overview', icon: 'globe' },
  { to: '/sessions', label: 'Session Explorer', icon: 'microscope' },
  { to: '/ingest', label: 'Live Ingest', icon: 'bolt' },
  { to: '/client', label: 'Client Dispatch', icon: 'send' },
  { to: '/rules', label: 'Compliance', icon: 'clipboard' },
  { to: '/ai-security', label: 'AI Security', icon: 'brain' },
];

export default function Sidebar({ isOpen, onClose, width = 264, onWidthChange }) {
  const [sysTime, setSysTime] = useState('');
  const [isResizing, setIsResizing] = useState(false);

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      const h = String(now.getUTCHours()).padStart(2, '0');
      const m = String(now.getUTCMinutes()).padStart(2, '0');
      const s = String(now.getUTCSeconds()).padStart(2, '0');
      setSysTime(`${h}:${m}:${s} UTC`);
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const handleMouseDown = (e) => {
    e.preventDefault();
    setIsResizing(true);
    const startX = e.clientX;
    const startWidth = width;

    const handleMouseMove = (moveEvent) => {
      const deltaX = moveEvent.clientX - startX;
      const nextWidth = Math.min(Math.max(startWidth + deltaX, 200), 480);
      if (onWidthChange) {
        onWidthChange(nextWidth);
      }
    };

    const handleMouseUp = () => {
      setIsResizing(false);
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseup', handleMouseUp);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    };

    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
    window.addEventListener('mousemove', handleMouseMove);
    window.addEventListener('mouseup', handleMouseUp);
  };

  const handleDoubleClick = () => {
    if (onWidthChange) onWidthChange(264);
  };

  return (
    <aside className={`app-sidebar ${isOpen ? 'open' : ''} ${isResizing ? 'resizing' : ''}`}>
      {/* Brand */}
      <div className="sidebar-brand">
        <div className="sidebar-brand-icon">
          <Logo size={34} />
        </div>
        <div className="sidebar-brand-text">
          <div className="sidebar-title">Secure SMTP</div>
          <div className="sidebar-subtitle">Cryptographic Intelligence</div>
        </div>
      </div>

      {/* Clock */}
      <div className="sidebar-clock">
        <span className="sidebar-clock-label">System Time</span>
        <span className="sidebar-clock-val">{sysTime || '00:00:00 UTC'}</span>
      </div>

      {/* Navigation */}
      <nav className="sidebar-nav">
        <div className="sidebar-section-label">Console</div>
        {NAV_ITEMS.map(({ to, label, icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) => `sidebar-link ${isActive ? 'active' : ''}`}
            onClick={onClose}
          >
            <span className="sidebar-link-icon">
              <Icon name={icon} size={16} />
            </span>
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="sidebar-spacer" />


      {/* Seal */}
      <div className="sidebar-seal">
        <div className="sidebar-seal-title">
          <Icon name="lock" size={13} />
          <span>Forensic Engine</span>
        </div>
        <div className="sidebar-seal-desc">
          Real-time passive cryptographic posture intelligence
        </div>
      </div>

      {/* Attribution */}
      <div className="sidebar-watermark">
        <span>Built by </span>
        <a
          href="https://github.com/sharmaharshit1661-web"
          target="_blank"
          rel="noopener noreferrer"
          className="sidebar-watermark-link"
        >
          @sharmaharshit1661
        </a>
      </div>

      {/* Resizer Handle */}
      <div
        className={`sidebar-resizer ${isResizing ? 'resizing' : ''}`}
        onMouseDown={handleMouseDown}
        onDoubleClick={handleDoubleClick}
        title="Drag to resize sidebar · Double-click to reset (264px)"
        aria-label="Resize sidebar"
        role="separator"
        aria-orientation="vertical"
      >
        <div className="sidebar-resizer-knob" />
      </div>
    </aside>
  );
}