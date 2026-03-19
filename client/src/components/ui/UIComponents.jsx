import React, { useEffect, useRef, useState } from 'react';
import styles from './UIComponents.module.scss';

/* ── Severity Badge ── */
export const SeverityBadge = ({ level, size = 'md', pulse = true }) => {
  if (!level) return null;
  const map = {
    Safe:     { cls: styles.safe,     icon: 'verified_user' },
    Medium:   { cls: styles.medium,   icon: 'warning' },
    High:     { cls: styles.high,     icon: 'gpp_bad' },
    Critical: { cls: styles.critical, icon: 'emergency_home' },
  };
  const { cls, icon } = map[level] || map.Medium;
  return (
    <span className={`${styles.badge} ${cls} ${styles[size]} ${level === 'Critical' && pulse ? styles.pulsing : ''}`}>
      <span className="material-symbols-rounded">{icon}</span>
      {level}
    </span>
  );
};

/* ── Animated Stat Card ── */
export const StatCard = ({ label, value, icon, color = 'blue', delta, loading }) => {
  const [displayed, setDisplayed] = useState(0);
  const [animated, setAnimated] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    if (loading || value === undefined) return;
    const observer = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting && !animated) {
        setAnimated(true);
        animateCount(0, Number(value), 1200);
      }
    }, { threshold: 0.3 });
    if (ref.current) observer.observe(ref.current);
    return () => observer.disconnect();
  }, [value, loading]);

  const animateCount = (from, to, duration) => {
    const start = performance.now();
    const step = (now) => {
      const progress = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setDisplayed(Math.round(from + (to - from) * eased));
      if (progress < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  };

  const colorMap = {
    blue:   { border: 'var(--accent-blue)',     bg: 'var(--accent-blue-dim)',     icon: 'var(--accent-blue)' },
    red:    { border: 'var(--threat-red)',       bg: 'var(--threat-red-dim)',      icon: 'var(--threat-red)' },
    amber:  { border: 'var(--warn-amber)',       bg: 'var(--warn-amber-dim)',      icon: 'var(--warn-amber)' },
    green:  { border: 'var(--safe-green)',       bg: 'var(--safe-green-dim)',      icon: 'var(--safe-green)' },
    purple: { border: 'var(--critical-purple)', bg: 'var(--critical-purple-dim)', icon: 'var(--critical-purple)' },
  };
  const c = colorMap[color] || colorMap.blue;

  return (
    <div
      ref={ref}
      className={styles.statCard}
      style={{ '--card-border': c.border, '--card-bg': c.bg }}
    >
      <div className={styles.statIcon} style={{ color: c.icon, background: c.bg }}>
        <span className="material-symbols-rounded">{icon}</span>
      </div>
      <div className={styles.statBody}>
        <div className={styles.statLabel}>{label}</div>
        <div className={`${styles.statValue} ${animated ? 'anim-count-up' : ''}`}>
          {loading ? <span className={styles.skeleton} style={{ width: 80, height: 28 }} /> : displayed}
        </div>
        {delta !== undefined && !loading && (
          <div className={`${styles.statDelta} ${delta >= 0 ? styles.up : styles.down}`}>
            <span className="material-symbols-rounded">{delta >= 0 ? 'trending_up' : 'trending_down'}</span>
            {Math.abs(delta)}% vs last week
          </div>
        )}
      </div>
    </div>
  );
};

/* ── Page Header ── */
export const PageHeader = ({ title, subtitle, actions, icon }) => (
  <div className={styles.pageHeader}>
    <div className={styles.pageHeaderLeft}>
      {icon && <span className={`material-symbols-rounded ${styles.pageIcon}`}>{icon}</span>}
      <div>
        <h1 className={styles.pageTitle}>{title}</h1>
        {subtitle && <p className={styles.pageSubtitle}>{subtitle}</p>}
      </div>
    </div>
    {actions && <div className={styles.pageActions}>{actions}</div>}
  </div>
);

/* ── Card ── */
export const Card = ({ children, className = '', noPad = false, glassEffect = false, borderColor }) => (
  <div
    className={`${styles.card} ${glassEffect ? styles.glass : ''} ${className}`}
    style={borderColor ? { '--left-border-color': borderColor } : {}}
  >
    <div className={noPad ? '' : styles.cardPad}>
      {children}
    </div>
  </div>
);

/* ── Loading Skeleton ── */
export const Skeleton = ({ width, height = 16, borderRadius = 4, className = '' }) => (
  <span
    className={`${styles.skeleton} ${className}`}
    style={{ width, height, borderRadius, display: 'inline-block' }}
  />
);

/* ── Empty State ── */
export const EmptyState = ({ icon = 'radar', title, message, action }) => (
  <div className={styles.emptyState}>
    <span className={`material-symbols-rounded ${styles.emptyIcon}`}>{icon}</span>
    <h3 className={styles.emptyTitle}>{title}</h3>
    {message && <p className={styles.emptyMsg}>{message}</p>}
    {action}
  </div>
);

/* ── Button ── */
export const Btn = ({ children, variant = 'primary', size = 'md', icon, loading, disabled, onClick, type = 'button', className = '' }) => (
  <button
    type={type}
    className={`${styles.btn} ${styles[`btn_${variant}`]} ${styles[`btn_${size}`]} ${className}`}
    disabled={disabled || loading}
    onClick={onClick}
  >
    {loading
      ? <span className="material-symbols-rounded" style={{ animation: 'spinLoader 0.8s linear infinite' }}>progress_activity</span>
      : icon && <span className="material-symbols-rounded">{icon}</span>}
    {children}
  </button>
);

/* ── Search Input ── */
export const SearchInput = ({ value, onChange, placeholder = 'Search...', className = '' }) => (
  <div className={`${styles.searchWrap} ${className}`}>
    <span className={`material-symbols-rounded ${styles.searchIcon}`}>search</span>
    <input
      type="text"
      className={styles.searchInput}
      value={value}
      onChange={e => onChange(e.target.value)}
      placeholder={placeholder}
    />
    {value && (
      <button className={styles.searchClear} onClick={() => onChange('')}>
        <span className="material-symbols-rounded">close</span>
      </button>
    )}
  </div>
);
