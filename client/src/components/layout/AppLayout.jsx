import React, { useEffect, useState } from 'react';
import { Outlet, NavLink, useLocation } from 'react-router-dom';

import { useTheme } from '../../context/ThemeContext';
import styles from './AppLayout.module.scss';

const NAV_ITEMS = [
  { to: '/dashboard', icon: 'radar', label: 'Dashboard' },
  { to: '/scanner', icon: 'bug_report', label: 'Scanner' },
  { to: '/history', icon: 'history', label: 'History' },
  { to: '/settings', icon: 'settings', label: 'Settings' },
];

const THEME_ICONS = { dark: 'dark_mode', light: 'light_mode', soc: 'monitor' };
const MOBILE_BREAKPOINT = 960;

export default function AppLayout() {
  const [expanded, setExpanded] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [isMobile, setIsMobile] = useState(() => typeof window !== 'undefined' && window.innerWidth <= MOBILE_BREAKPOINT);
  const { theme, cycleTheme, themes } = useTheme();
  const location = useLocation();

  useEffect(() => {
    const syncViewport = () => {
      const mobile = window.innerWidth <= MOBILE_BREAKPOINT;
      setIsMobile(mobile);
      if (!mobile) {
        setMobileOpen(false);
      }
    };

    syncViewport();
    window.addEventListener('resize', syncViewport);
    return () => window.removeEventListener('resize', syncViewport);
  }, []);

  useEffect(() => {
    setMobileOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    if (!mobileOpen) return undefined;

    const onKeyDown = (event) => {
      if (event.key === 'Escape') {
        setMobileOpen(false);
      }
    };

    window.addEventListener('keydown', onKeyDown);
    document.body.style.overflow = 'hidden';

    return () => {
      window.removeEventListener('keydown', onKeyDown);
      document.body.style.overflow = '';
    };
  }, [mobileOpen]);

  const toggleSidebar = () => {
    if (isMobile) {
      setMobileOpen((open) => !open);
      return;
    }

    setExpanded((open) => !open);
  };

  const sidebarClassName = [
    styles.sidebar,
    expanded ? styles.expanded : '',
    mobileOpen ? styles.mobileOpen : '',
  ].filter(Boolean).join(' ');

  return (
    <div className={styles.root}>
      <div className={styles.meshBg} aria-hidden="true" />
      {mobileOpen && <button className={styles.overlay} aria-label="Close sidebar" onClick={() => setMobileOpen(false)} />}

      <aside
        className={sidebarClassName}
        onMouseEnter={() => !isMobile && setExpanded(true)}
        onMouseLeave={() => !isMobile && setExpanded(false)}
      >
        <div className={styles.logo}>
          <span className={`material-symbols-rounded ${styles.logoIcon}`}>radar</span>
          <span className={styles.logoText}>HoneyScan</span>
          {isMobile && (
            <button
              type="button"
              className={styles.closeBtn}
              onClick={() => setMobileOpen(false)}
              aria-label="Close sidebar"
            >
              <span className="material-symbols-rounded">close</span>
            </button>
          )}
        </div>

        <nav className={styles.nav}>
          {NAV_ITEMS.map(({ to, icon, label }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) => `${styles.navItem} ${isActive ? styles.active : ''}`}
            >
              <span className={`material-symbols-rounded ${styles.navIcon}`}>{icon}</span>
              <span className={styles.navLabel}>{label}</span>
            </NavLink>
          ))}
        </nav>

        <div className={styles.sidebarBottom}>
          <button
            type="button"
            className={styles.iconBtn}
            onClick={cycleTheme}
            title={`Switch to ${Object.keys(themes).find((t) => t !== theme) ?? 'dark'} theme`}
          >
            <span className="material-symbols-rounded">{THEME_ICONS[theme]}</span>
            <span className={styles.navLabel}>{themes[theme]?.label}</span>
          </button>

            <div className={styles.userChip}>
              <span className={`material-symbols-rounded ${styles.userIcon}`}>account_circle</span>
              <div className={styles.userInfo}>
                <span className={styles.userName}>Guest Analyst</span>
                <span className={styles.userRole}>Public Mode</span>
              </div>
            </div>
        </div>
      </aside>

      <main className={styles.main}>
        <header className={styles.topbar}>
          <div className={styles.topbarLeft}>
            <button
              type="button"
              className={styles.menuBtn}
              onClick={toggleSidebar}
              aria-label={isMobile ? (mobileOpen ? 'Close sidebar' : 'Open sidebar') : (expanded ? 'Collapse sidebar' : 'Expand sidebar')}
              aria-expanded={isMobile ? mobileOpen : expanded}
            >
              <span className="material-symbols-rounded">menu</span>
            </button>
            <div className={styles.topbarBrand}>
              <span className={`material-symbols-rounded ${styles.topbarBrandIcon}`}>radar</span>
              <div className={styles.topbarCopy}>
                <span className={styles.eyebrow}>HoneyScan</span>
                <span className={styles.topbarLabel}>Threat Detection Platform</span>
              </div>
            </div>
          </div>
       </header>

        <div className={styles.content}>
          <Outlet />
        </div>

        <footer className={styles.footer}>
          <div className={styles.footerBrand}>
            <span className="material-symbols-rounded">radar</span>
            <span>HoneyScan</span>
          </div>
          <div className={styles.footerMeta}>
            <span>Realtime phishing and malware triage workspace</span>
            <span>Copyright {new Date().getFullYear()}</span>
          </div>
        </footer>
      </main>
    </div>
  );
}
