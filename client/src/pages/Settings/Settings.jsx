import React, { useState, useEffect, useCallback } from 'react';
import { useTheme } from '../../context/ThemeContext';
import { useToast } from '../../context/ToastContext';
import api from '../../services/api';
import styles from './Settings.module.scss';

const DEFAULT_SCAN_WEIGHTS = { ioc: 30, behavior: 25, network: 20, reputation: 25 };
const DEFAULT_SCAN_DEFAULTS = { wireshark: true, suricata: true, sandbox: true, maxConcurrent: 3 };
const DEFAULT_TOAST_PREFS = { safe: true, medium: true, high: true, critical: true };

const THEME_PREVIEW_COLORS = {
  dark: { bg: '#0a0a0a', border: '#1e1e1e', text: '#e0e0e0', accent: '#3b82f6' },
  light: { bg: '#ffffff', border: '#e5e7eb', text: '#111827', accent: '#2563eb' },
  soc: { bg: '#000000', border: '#00ff41', text: '#00ff41', accent: '#00ff41' }
};

export default function Settings() {
  const { theme, setTheme, themes } = useTheme();
  const { toast } = useToast();

  // ── State ──
  const [vtApiKey, setVtApiKey] = useState('');
  const [showVtKey, setShowVtKey] = useState(false);
  const [scanWeights, setScanWeights] = useState(DEFAULT_SCAN_WEIGHTS);
  const [scanDefaults, setScanDefaults] = useState(DEFAULT_SCAN_DEFAULTS);
  const [toastPrefs, setToastPrefs] = useState(DEFAULT_TOAST_PREFS);
  const [isSaving, setIsSaving] = useState(false);
  const [totalWeight, setTotalWeight] = useState(100);

  // ── Load from localStorage ──
  useEffect(() => {
    const loadSettings = () => {
      try {
        const saved = {
          vtApiKey: localStorage.getItem('settings.vtApiKey') || '',
          scanWeights: JSON.parse(localStorage.getItem('settings.scanWeights') || '{}'),
          scanDefaults: JSON.parse(localStorage.getItem('settings.scanDefaults') || '{}'),
          toastPrefs: JSON.parse(localStorage.getItem('settings.toastPrefs') || '{}')
        };
        setVtApiKey(saved.vtApiKey);
        setScanWeights({ ...DEFAULT_SCAN_WEIGHTS, ...saved.scanWeights });
        setScanDefaults({ ...DEFAULT_SCAN_DEFAULTS, ...saved.scanDefaults });
        setToastPrefs({ ...DEFAULT_TOAST_PREFS, ...saved.toastPrefs });
      } catch {}
    };
    loadSettings();
  }, []);

  // ── Update total weight ──
  useEffect(() => {
    const total = Object.values(scanWeights).reduce((sum, w) => sum + Number(w), 0);
    setTotalWeight(Math.min(100, Math.max(0, total)));
  }, [scanWeights]);

  // ── Handlers ──
  const handleWeightChange = useCallback((key, value) => {
    setScanWeights(prev => ({ ...prev, [key]: Number(value) }));
  }, []);

  const handleSave = useCallback(async () => {
    setIsSaving(true);
    try {
      // Save to localStorage
      localStorage.setItem('settings.vtApiKey', vtApiKey);
      localStorage.setItem('settings.scanWeights', JSON.stringify(scanWeights));
      localStorage.setItem('settings.scanDefaults', JSON.stringify(scanDefaults));
      localStorage.setItem('settings.toastPrefs', JSON.stringify(toastPrefs));

      // Optional: Save to API
      // await api.post('/settings', { vtApiKey, scanWeights, scanDefaults, toastPrefs });

      toast.success('Settings saved successfully!');
      
      // Apply theme if changed
      if (localStorage.getItem('hs_theme') !== theme) {
        setTheme(localStorage.getItem('hs_theme'));
      }
    } catch (error) {
      toast.error('Failed to save settings');
    } finally {
      setIsSaving(false);
    }
  }, [vtApiKey, scanWeights, scanDefaults, toastPrefs, theme, setTheme, toast]);

  const handleReset = useCallback(() => {
    if (confirm('Reset all settings to defaults?')) {
      localStorage.removeItem('settings.vtApiKey');
      localStorage.removeItem('settings.scanWeights');
      localStorage.removeItem('settings.scanDefaults');
      localStorage.removeItem('settings.toastPrefs');
      setVtApiKey('');
      setScanWeights(DEFAULT_SCAN_WEIGHTS);
      setScanDefaults(DEFAULT_SCAN_DEFAULTS);
      setToastPrefs(DEFAULT_TOAST_PREFS);
      toast.success('Settings reset to defaults');
    }
  }, [toast]);

  const validateVtKey = (key) => {
    return key.length >= 32 && key.includes('YOUR_VT_API_KEY');
  };

  const themePreviewStyle = (t) => ({
    backgroundColor: THEME_PREVIEW_COLORS[t]?.bg || '#ffffff',
    color: THEME_PREVIEW_COLORS[t]?.text || '#000000',
    borderLeftColor: THEME_PREVIEW_COLORS[t]?.accent || '#3b82f6'
  });

  return (
    <div className={styles.page}>
      <div className={styles.grid}>
        
        {/* ── Theme Section ── */}
        <section className={styles.section}>
          <div className={styles.sectionHead}>
            <h2 className={styles.sectionTitle}>
              <span className="material-symbols-rounded">palette</span>
              Appearance
            </h2>
            <button className={styles.resetBtn} onClick={handleReset}>Reset</button>
          </div>
          <p className={styles.sectionHint}>Select your preferred workspace theme</p>
          
          <div className={styles.themeCards}>
            {Object.entries(themes).map(([key, data]) => (
              <button
                key={key}
                className={`${styles.themeCard} ${theme === key ? styles.activeTheme : ''}`}
                onClick={() => setTheme(key)}
              >
                <span className="material-symbols-rounded">{data.icon}</span>
                <div>
                  <div className={styles.themeName}>{data.label}</div>
                  <div className={styles.themeDesc}>{data.description}</div>
                </div>
              </button>
            ))}
          </div>

          <div className={styles.themePreview}>
            <div className={styles.previewLabel}>Preview</div>
            <div className={styles.previewCards}>
              <div className={styles.previewCard} style={themePreviewStyle(theme)}>
                <span>Sample Card</span>
                <span className={styles.previewScore}>87</span>
              </div>
            </div>
          </div>
        </section>

        {/* ── VirusTotal API ── */}
        <section className={styles.section}>
          <h2 className={styles.sectionTitle}>
            <span className="material-symbols-rounded">api</span>
            VirusTotal
          </h2>
          <p className={styles.sectionHint}>API key for reputation lookups (required for Analysis)</p>
          
          <div className={styles.vtWrap}>
            <label className={styles.fieldLabel}>API Key</label>
            <div className={styles.vtInput}>
              <input
                type={showVtKey ? 'text' : 'password'}
                className={styles.textInput}
                value={vtApiKey}
                onChange={(e) => setVtApiKey(e.target.value)}
                placeholder="pk_..."
              />
              <button
                type="button"
                className={styles.eyeBtn}
                onClick={() => setShowVtKey(!showVtKey)}
              >
                <span className="material-symbols-rounded">
                  {showVtKey ? 'visibility_off' : 'visibility'}
                </span>
              </button>
            </div>
            {vtApiKey && !validateVtKey(vtApiKey) && (
              <div className={styles.fieldHint} style={{color: 'var(--threat-red)'}}>
                Invalid VirusTotal API key format
              </div>
            )}
          </div>
        </section>
      </div>

      <div className={styles.grid}>
        {/* ── Risk Scoring Weights ── */}
        <section className={styles.section}>
          <h2 className={styles.sectionTitle}>
            <span className="material-symbols-rounded">tune</span>
            Risk Weights
          </h2>
          <p className={styles.sectionHint}>Adjust scoring algorithm priorities (total: 100%)</p>
          
          <div className={styles.weightSliders}>
            {Object.entries(DEFAULT_SCAN_WEIGHTS).map(([key, def]) => (
              <div key={key} className={styles.sliderRow}>
                <span className={styles.sliderLabel}>
                  {key === 'ioc' ? 'IOCs' : key === 'behavior' ? 'Behavior' : key === 'network' ? 'Network' : 'Reputation'}
                </span>
                <input
                  type="range"
                  min="0"
                  max="100"
                  step="1"
                  value={scanWeights[key]}
                  className={styles.slider}
                  onChange={(e) => handleWeightChange(key, e.target.value)}
                />
                <span className={styles.sliderVal}>{scanWeights[key]}%</span>
              </div>
            ))}
          </div>
          <div className={styles.totalCode}>Total: {totalWeight}%</div>
        </section>

        {/* ── Scan Defaults ── */}
        <section className={styles.section}>
          <h2 className={styles.sectionTitle}>
            <span className="material-symbols-rounded">settings_overscan</span>
            Scan Defaults
          </h2>
          
          <div className={styles.fieldGrid}>
            <div className={styles.fieldItem}>
              <label className={styles.toggleLabel}>
                <input
                  type="checkbox"
                  checked={scanDefaults.wireshark}
                  onChange={(e) => setScanDefaults(prev => ({...prev, wireshark: e.target.checked}))}
                />
                Wireshark Capture
              </label>
              <label className={styles.toggleLabel}>
                <input
                  type="checkbox"
                  checked={scanDefaults.suricata}
                  onChange={(e) => setScanDefaults(prev => ({...prev, suricata: e.target.checked}))}
                />
                Suricata IDS
              </label>
            </div>
            <div className={styles.fieldItem}>
              <label className={styles.toggleLabel}>
                <input
                  type="checkbox"
                  checked={scanDefaults.sandbox}
                  onChange={(e) => setScanDefaults(prev => ({...prev, sandbox: e.target.checked}))}
                />
                VM Sandbox
              </label>
              <label className={styles.fieldLabel}>Max Concurrent</label>
              <input
                type="number"
                min="1"
                max="10"
                value={scanDefaults.maxConcurrent}
                onChange={(e) => setScanDefaults(prev => ({...prev, maxConcurrent: Number(e.target.value)}))}
                className={styles.textInput}
              />
            </div>
          </div>
        </section>
      </div>

      {/* ── Toast Preferences ── */}
      <section className={styles.section}>
        <h2 className={styles.sectionTitle}>
          <span className="material-symbols-rounded">notifications</span>
          Notifications
        </h2>
        <p className={styles.sectionHint}>Select toast notification levels to show</p>
        
        <div className={styles.toastPrefs}>
          {Object.entries(DEFAULT_TOAST_PREFS).map(([level]) => (
            <label key={level} className={styles.toastPref}>
              <input
                type="checkbox"
                checked={toastPrefs[level]}
                onChange={(e) => setToastPrefs(prev => ({...prev, [level]: e.target.checked}))}
              />
              <span className={`${styles.toastLevel} level_${level}`}>{level.toUpperCase()}</span>
            </label>
          ))}
        </div>
      </section>

      {/* ── Save Bar ── */}
      <div className={styles.saveBar}>
        <button className={styles.resetBtn} onClick={handleReset} disabled={isSaving}>
          Reset Defaults
        </button>
        <button 
          onClick={handleSave} 
          disabled={isSaving || totalWeight !== 100}
          style={{marginLeft: '12px', padding: '8px 20px', background: 'var(--accent-blue)', color: 'white', border: 'none', borderRadius: '3px'}}
        >
          {isSaving ? 'Saving...' : 'Save All Settings'}
        </button>
      </div>
    </div>
  );
}

