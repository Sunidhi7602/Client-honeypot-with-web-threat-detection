import React, { useState, useEffect } from 'react';
import { PageHeader, Btn } from '../../components/ui/UIComponents';
import { useAuth } from '../../context/AuthContext';
import { useTheme } from '../../context/ThemeContext';
import { useToast } from '../../context/ToastContext';
import styles from './Settings.module.scss';

const DEFAULT_WEIGHTS = {
  scriptCount: 0.25, redirectCount: 0.20, hiddenIframes: 0.20,
  downloadAttempts: 0.15, domMutationRate: 0.10, externalScripts: 0.10,
};

const WEIGHT_LABELS = {
  scriptCount: 'Script Executions', redirectCount: 'Redirect Hops',
  hiddenIframes: 'Hidden iFrames', downloadAttempts: 'Download Attempts',
  domMutationRate: 'DOM Mutation Rate', externalScripts: 'External Scripts',
};

export default function Settings() {
  const { user, updateSettings } = useAuth();
  const { theme, setTheme, themes } = useTheme();
  const { toast } = useToast();

  const [vtKey, setVtKey]         = useState('');
  const [showKey, setShowKey]     = useState(false);
  const [weights, setWeights]     = useState({ ...DEFAULT_WEIGHTS });
  const [scanDefaults, setScanDefaults] = useState({
    observationWindow: 30, maxRedirectDepth: 5,
    userAgent: 'HoneyScan/1.0 (Research Scanner)', enableSuricata: false,
  });
  const [toastPrefs, setToastPrefs] = useState({
    safe: false, medium: true, high: true, critical: true,
  });
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!user?.settings) return;
    const s = user.settings;
    if (s.riskWeights) setWeights({ ...DEFAULT_WEIGHTS, ...s.riskWeights });
    if (s.scanDefaults) setScanDefaults(d => ({ ...d, ...s.scanDefaults }));
    if (s.toastPreferences) setToastPrefs(d => ({ ...d, ...s.toastPreferences }));
  }, [user]);

  const totalWeight = Object.values(weights).reduce((a, b) => a + b, 0);

  const handleSave = async () => {
    setSaving(true);
    try {
      await updateSettings({
        theme,
        virusTotalApiKey: vtKey || undefined,
        riskWeights: weights,
        scanDefaults,
        toastPreferences: toastPrefs,
      });
      toast.success('Settings saved successfully');
    } catch {
      toast.error('Failed to save settings');
    } finally {
      setSaving(false);
    }
  };

  const resetWeights = () => setWeights({ ...DEFAULT_WEIGHTS });

  return (
    <div className={styles.page}>
      <PageHeader title="Settings" subtitle="Configure your HoneyScan analyst environment" icon="settings" />

      <div className={styles.grid}>
        {/* ── Theme Switcher ── */}
        <section className={styles.section}>
          <h2 className={styles.sectionTitle}>
            <span className="material-symbols-rounded">palette</span> Appearance
          </h2>
          <div className={styles.themeCards}>
            {Object.entries(themes).map(([key, meta]) => (
              <button
                key={key}
                className={`${styles.themeCard} ${theme === key ? styles.activeTheme : ''}`}
                onClick={() => setTheme(key)}
                data-theme-preview={key}
              >
                <span className="material-symbols-rounded">{meta.icon}</span>
                <div>
                  <div className={styles.themeName}>{meta.label}</div>
                  <div className={styles.themeDesc}>{meta.description}</div>
                </div>
                {theme === key && <span className="material-symbols-rounded" style={{ marginLeft: 'auto', color: 'var(--accent-blue)' }}>check_circle</span>}
              </button>
            ))}
          </div>
          {/* Live preview */}
          <div className={styles.themePreview}>
            <div className={styles.previewLabel}>Live Preview</div>
            <div className={styles.previewCards}>
              <div className={styles.previewCard} style={{ borderLeftColor: 'var(--safe-green)' }}>
                <span style={{ color: 'var(--safe-green)' }}>Safe</span>
                <span className={styles.previewScore}>12</span>
              </div>
              <div className={styles.previewCard} style={{ borderLeftColor: 'var(--warn-amber)' }}>
                <span style={{ color: 'var(--warn-amber)' }}>Medium</span>
                <span className={styles.previewScore}>44</span>
              </div>
              <div className={styles.previewCard} style={{ borderLeftColor: 'var(--threat-red)' }}>
                <span style={{ color: 'var(--threat-red)' }}>Critical</span>
                <span className={styles.previewScore}>89</span>
              </div>
            </div>
          </div>
        </section>

        {/* ── VirusTotal API Key ── */}
        <section className={styles.section}>
          <h2 className={styles.sectionTitle}>
            <span className="material-symbols-rounded">vpn_key</span> VirusTotal Integration
          </h2>
          <div className={styles.vtWrap}>
            <label className={styles.fieldLabel}>API Key (v3)</label>
            <div className={styles.vtInput}>
              <input
                type={showKey ? 'text' : 'password'}
                className={styles.textInput}
                placeholder={user?.settings?.virusTotalApiKey ? '••••••••••••••••' : 'Enter your VirusTotal API key'}
                value={vtKey}
                onChange={e => setVtKey(e.target.value)}
              />
              <button className={styles.eyeBtn} onClick={() => setShowKey(s => !s)}>
                <span className="material-symbols-rounded">{showKey ? 'visibility_off' : 'visibility'}</span>
              </button>
            </div>
            <p className={styles.fieldHint}>
              Used for IoC enrichment lookups. Without a key, the VirusTotal button opens the web interface.
              Get a free key at <a href="https://virustotal.com" target="_blank" rel="noreferrer">virustotal.com</a>.
            </p>
          </div>
        </section>

        {/* ── Risk Score Weights ── */}
        <section className={styles.section}>
          <div className={styles.sectionHead}>
            <h2 className={styles.sectionTitle}>
              <span className="material-symbols-rounded">tune</span> Risk Score Weights
            </h2>
            <button className={styles.resetBtn} onClick={resetWeights}>Reset defaults</button>
          </div>
          <p className={styles.sectionHint}>
            Adjust signal importance. Weights are auto-normalized — total: <code className={styles.totalCode} style={{ color: Math.abs(totalWeight - 1) < 0.01 ? 'var(--safe-green)' : 'var(--warn-amber)' }}>{totalWeight.toFixed(2)}</code>
          </p>
          <div className={styles.weightSliders}>
            {Object.entries(weights).map(([signal, val]) => (
              <div key={signal} className={styles.sliderRow}>
                <label className={styles.sliderLabel}>{WEIGHT_LABELS[signal]}</label>
                <input
                  type="range" min={0} max={0.5} step={0.01}
                  value={val}
                  onChange={e => setWeights(w => ({ ...w, [signal]: parseFloat(e.target.value) }))}
                  className={styles.slider}
                />
                <span className={styles.sliderVal}>{(val * 100).toFixed(0)}%</span>
              </div>
            ))}
          </div>
        </section>

        {/* ── Scan Defaults ── */}
        <section className={styles.section}>
          <h2 className={styles.sectionTitle}>
            <span className="material-symbols-rounded">settings_suggest</span> Scan Defaults
          </h2>
          <div className={styles.fieldGrid}>
            <div className={styles.fieldItem}>
              <label className={styles.fieldLabel}>Observation Window (seconds)</label>
              <input type="number" className={styles.textInput} min={10} max={120}
                value={scanDefaults.observationWindow}
                onChange={e => setScanDefaults(d => ({ ...d, observationWindow: +e.target.value }))} />
            </div>
            <div className={styles.fieldItem}>
              <label className={styles.fieldLabel}>Max Redirect Depth</label>
              <input type="number" className={styles.textInput} min={1} max={20}
                value={scanDefaults.maxRedirectDepth}
                onChange={e => setScanDefaults(d => ({ ...d, maxRedirectDepth: +e.target.value }))} />
            </div>
            <div className={styles.fieldItem} style={{ gridColumn: '1/-1' }}>
              <label className={styles.fieldLabel}>Default User Agent</label>
              <input type="text" className={styles.textInput}
                value={scanDefaults.userAgent}
                onChange={e => setScanDefaults(d => ({ ...d, userAgent: e.target.value }))} />
            </div>
            <div className={styles.fieldItem} style={{ gridColumn: '1/-1' }}>
              <label className={styles.toggleLabel}>
                <input type="checkbox" checked={scanDefaults.enableSuricata}
                  onChange={e => setScanDefaults(d => ({ ...d, enableSuricata: e.target.checked }))} />
                Enable Suricata IDS by default on Deep Scans
              </label>
            </div>
          </div>
        </section>

        {/* ── Toast Preferences ── */}
        <section className={styles.section}>
          <h2 className={styles.sectionTitle}>
            <span className="material-symbols-rounded">notifications</span> Notification Preferences
          </h2>
          <div className={styles.toastPrefs}>
            {Object.entries(toastPrefs).map(([level, enabled]) => (
              <label key={level} className={styles.toastPref}>
                <input type="checkbox" checked={enabled}
                  onChange={e => setToastPrefs(p => ({ ...p, [level]: e.target.checked }))} />
                <span className={`${styles.toastLevel} ${styles[`level_${level}`]}`}>{level}</span>
                <span style={{ color: 'var(--text-secondary)', fontSize: 13 }}>severity notifications</span>
              </label>
            ))}
          </div>
        </section>
      </div>

      {/* Save Button */}
      <div className={styles.saveBar}>
        <Btn variant="primary" size="lg" icon="save" loading={saving} onClick={handleSave}>
          Save All Settings
        </Btn>
      </div>
    </div>
  );
}
