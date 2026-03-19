import React from 'react';
import { useToast } from '../../context/ToastContext';
import styles from './ToastContainer.module.scss';

const ICONS = {
  info:     'info',
  success:  'check_circle',
  warn:     'warning',
  error:    'error',
  critical: 'emergency_home',
};

export default function ToastContainer() {
  const { toasts, removeToast } = useToast();

  return (
    <div className={styles.container} aria-live="polite">
      {toasts.map(({ id, message, type, duration }) => (
        <div key={id} className={`${styles.toast} ${styles[type]}`}>
          <span className={`material-symbols-rounded ${styles.icon}`}>{ICONS[type] || 'info'}</span>
          <span className={styles.message}>{message}</span>
          <button className={styles.close} onClick={() => removeToast(id)}>
            <span className="material-symbols-rounded">close</span>
          </button>
          {duration > 0 && (
            <div
              className={styles.progress}
              style={{ animationDuration: `${duration}ms` }}
            />
          )}
        </div>
      ))}
    </div>
  );
}
