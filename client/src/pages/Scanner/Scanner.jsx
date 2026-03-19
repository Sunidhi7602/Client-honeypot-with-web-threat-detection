import React, { useState, useRef, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { PageHeader, Btn, Card } from '../../components/ui/UIComponents';
import { useToast } from '../../context/ToastContext';
import { getSocket, subscribeScan, unsubscribeScan } from '../../services/socket';
import api from '../../services/api';
import styles from './Scanner.module.scss';

const STEPS = [
  { id: 0, label: 'VM Restore',         icon: 'computer'        },
  { id: 1, label: 'Browser Navigation', icon: 'travel_explore'  },
  { id: 2, label: 'Signal Extraction',  icon: 'analytics'       },
  { id: 3, label: 'Wireshark Capture',  icon: 'network_check'   },
  { id: 4, label: 'Suricata Check',     icon: 'security'        },
  { id: 5, label: 'Risk Scoring',       icon: 'score'           },
  { id: 6, label: 'IoC Extraction',     icon: 'bug_report'      },
];

const LOG_COLORS = {
  info:  'var(--text-secondary)',
  warn:  'var(--warn-amber)',
  error: 'var(--threat-red)',
  alert: 'var(--threat-red)',
  debug: 'var(--text-muted)',
};

function validateUrl(url) {
  try {
    const u = new URL(url);
    return ['http:', 'https:'].includes(u.protocol);
  } catch { return false; }
}

export default function Scanner() {
  const navigate = useNavigate();
  const { toast } = useToast();

  const [url, setUrl]             = useState('');
  const [urlValid, setUrlValid]   = useState(null);
  const [scanType, setScanType]   = useState('quick');
  const [opts, setOpts]           = useState({
    redirectDepth: 5, observationWindow: 30,
    userAgent: 'HoneyScan/1.0 (Research Scanner)',
    enableSuricata: false,
  });

  const [scanning, setScanning]       = useState(false);
  const [scanId, setScanId]           = useState(null);
  const [currentStep, setCurrentStep] = useState(-1);
  const [stepStates, setStepStates]   = useState({});  // {step: 'active'|'done'|'error'}
  const [logs, setLogs]               = useState([]);
  const [netRequests, setNetRequests] = useState([]);
  const [completed, setCompleted]     = useState(null);

  const logsEndRef = useRef(null);

  useEffect(() => {
    if (url.length > 3) setUrlValid(validateUrl(url));
    else setUrlValid(null);
  }, [url]);

  // Auto-scroll terminal
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  // Socket.IO subscription
  useEffect(() => {
    if (!scanId) return;
    const socket = getSocket();
    subscribeScan(scanId);

    socket.on('scan:progress', ({ level, message, timestamp }) => {
      setLogs(prev => [...prev, { level, message, timestamp: timestamp || new Date(), id: Date.now() + Math.random() }]);
    });

    socket.on('scan:step', ({ step, name, status }) => {
      setCurrentStep(step);
      setStepStates(prev => ({ ...prev, [step]: status }));
      if (status === 'active') {
        toast.info(`Step ${step + 1}: ${name}`, 3000);
      }
    });

    socket.on('scan:network', (req) => {
      setNetRequests(prev => [req, ...prev].slice(0, 200));
    });

    socket.on('scan:complete', (data) => {
      setCompleted(data);
      setScanning(false);
      setStepStates(prev => {
        const s = { ...prev };
        STEPS.forEach(st => { if (!s[st.id]) s[st.id] = 'done'; });
        return s;
      });
      const severity = data.riskLevel;
      if (severity === 'Critical') toast.critical(`CRITICAL THREAT — Score: ${data.threatScore}`, 0);
      else if (severity === 'High') toast.error(`High Threat Detected — Score: ${data.threatScore}`, 8000);
      else if (severity === 'Medium') toast.warn(`Medium Risk — Score: ${data.threatScore}`, 6000);
      else toast.success(`Scan complete — Score: ${data.threatScore} (${severity})`, 5000);
    });

    socket.on('scan:error', ({ error }) => {
      setScanning(false);
      toast.error(`Scan failed: ${error}`, 0);
      setLogs(prev => [...prev, { level: 'error', message: `SCAN FAILED: ${error}`, timestamp: new Date(), id: Date.now() }]);
    });

    return () => {
      socket.off('scan:progress');
      socket.off('scan:step');
      socket.off('scan:network');
      socket.off('scan:complete');
      socket.off('scan:error');
      unsubscribeScan(scanId);
    };
  }, [scanId]);

  const handleSubmit = async () => {
    if (!urlValid) { toast.warn('Enter a valid URL with http:// or https://'); return; }

    setScanning(true);
    setLogs([]);
    setNetRequests([]);
    setStepStates({});
    setCurrentStep(-1);
    setCompleted(null);

    try {
      const { data } = await api.post('/scans', {
        url, scanType,
        options: { ...opts, enableWireshark: scanType === 'deep' },
      });
      setScanId(data.scan._id);
      setLogs([{ level: 'info', message: `[Queue] Scan job enqueued (ID: ${data.scan._id})`, timestamp: new Date(), id: 1 }]);
      toast.info('Scan queued successfully', 3000);
    } catch (err) {
      setScanning(false);
      toast.error(err.response?.data?.error || 'Failed to submit scan');
    }
  };

  const handleViewResults = () => {
    if (completed?.scanId) navigate(`/analysis/${completed.scanId}`);
    else if (scanId) navigate(`/analysis/${scanId}`);
  };

  return (
    <div className={styles.page}>
      <PageHeader title="URL Scanner" subtitle="Submit a suspicious URL for sandbox analysis" icon="bug_report" />

      <div className={styles.layout}>
        {/* ── Left Panel: Config ── */}
        <div className={styles.configPanel}>
          {/* URL Input */}
          <Card>
            <div className={styles.inputSection}>
              <label className={styles.inputLabel}>Target URL</label>
              <div className={`${styles.urlWrap} ${urlValid === true ? styles.valid : urlValid === false ? styles.invalid : ''}`}>
                <span className="material-symbols-rounded">link</span>
                <input
                  type="text"
                  className={styles.urlInput}
                  placeholder="https://suspicious-domain.example.com/payload"
                  value={url}
                  onChange={e => setUrl(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && handleSubmit()}
                  disabled={scanning}
                  spellCheck={false}
                />
                {urlValid === true && <span className="material-symbols-rounded" style={{ color: 'var(--safe-green)' }}>check_circle</span>}
                {urlValid === false && <span className="material-symbols-rounded" style={{ color: 'var(--threat-red)' }}>error</span>}
              </div>
              {urlValid === false && <p className={styles.urlError}>Enter a valid URL starting with http:// or https://</p>}
            </div>

            {/* Scan Type */}
            <div className={styles.scanTypeRow}>
              <button
                className={`${styles.scanTypeBtn} ${scanType === 'quick' ? styles.selected : ''}`}
                onClick={() => setScanType('quick')}
                disabled={scanning}
              >
                <span className="material-symbols-rounded">flash_on</span>
                <div>
                  <div className={styles.stLabel}>Quick Scan</div>
                  <div className={styles.stDesc}>Puppeteer + CDP signals only</div>
                </div>
              </button>
              <button
                className={`${styles.scanTypeBtn} ${scanType === 'deep' ? styles.selected : ''}`}
                onClick={() => setScanType('deep')}
                disabled={scanning}
              >
                <span className="material-symbols-rounded">crisis_alert</span>
                <div>
                  <div className={styles.stLabel}>Deep Scan</div>
                  <div className={styles.stDesc}>+ Wireshark + Suricata IDS</div>
                </div>
              </button>
            </div>

            {/* Options */}
            <div className={styles.optGrid}>
              <div className={styles.optItem}>
                <label>Redirect Depth</label>
                <input type="number" min={1} max={20} value={opts.redirectDepth}
                  onChange={e => setOpts(o => ({ ...o, redirectDepth: +e.target.value }))}
                  disabled={scanning} className={styles.optInput} />
              </div>
              <div className={styles.optItem}>
                <label>Observation Window (s)</label>
                <input type="number" min={10} max={120} value={opts.observationWindow}
                  onChange={e => setOpts(o => ({ ...o, observationWindow: +e.target.value }))}
                  disabled={scanning} className={styles.optInput} />
              </div>
              <div className={styles.optItem} style={{ gridColumn: '1/-1' }}>
                <label>User Agent</label>
                <input type="text" value={opts.userAgent}
                  onChange={e => setOpts(o => ({ ...o, userAgent: e.target.value }))}
                  disabled={scanning} className={styles.optInput} />
              </div>
              {scanType === 'deep' && (
                <div className={styles.toggleRow}>
                  <label className={styles.toggleLabel}>
                    <input type="checkbox" checked={opts.enableSuricata}
                      onChange={e => setOpts(o => ({ ...o, enableSuricata: e.target.checked }))}
                      disabled={scanning} />
                    <span>Enable Suricata IDS alerts</span>
                  </label>
                </div>
              )}
            </div>

            {/* Submit */}
            <Btn
              variant={scanning ? 'ghost' : 'primary'} size="lg"
              icon={scanning ? 'hourglass_top' : 'play_arrow'}
              loading={scanning} onClick={handleSubmit}
              className={styles.submitBtn}
              disabled={scanning || urlValid !== true}
            >
              {scanning ? 'Scanning...' : 'Launch Scan'}
            </Btn>

            {completed && (
              <Btn variant="secondary" size="md" icon="analytics" onClick={handleViewResults} className={styles.viewBtn}>
                View Full Analysis
              </Btn>
            )}
          </Card>

          {/* ── Stepper ── */}
          <Card>
            <div className={styles.cardHeader}><h2>Scan Pipeline</h2></div>
            <div className={styles.stepper}>
              {STEPS.map((step) => {
                const state = stepStates[step.id];
                const isActive = state === 'active';
                const isDone   = state === 'done';
                const isError  = state === 'error';
                return (
                  <div key={step.id} className={`${styles.step} ${isActive ? styles.stepActive : isDone ? styles.stepDone : isError ? styles.stepError : ''}`}>
                    <div className={styles.stepIconWrap}>
                      {isDone
                        ? <span className="material-symbols-rounded" style={{ color: 'var(--safe-green)' }}>check_circle</span>
                        : isError
                        ? <span className="material-symbols-rounded" style={{ color: 'var(--threat-red)' }}>error</span>
                        : <span className="material-symbols-rounded">{step.icon}</span>}
                      {isActive && <span className={styles.stepRing} />}
                    </div>
                    <span className={styles.stepLabel}>{step.label}</span>
                    {step.id < STEPS.length - 1 && <div className={`${styles.stepLine} ${isDone ? styles.lineActive : ''}`} />}
                  </div>
                );
              })}
            </div>
          </Card>
        </div>

        {/* ── Right Panel: Terminal + Network ── */}
        <div className={styles.outputPanel}>
          {/* Terminal */}
          <Card noPad>
            <div className={styles.terminalHeader}>
              <div className={styles.termDots}>
                <span style={{ background: '#ff5f57' }} />
                <span style={{ background: '#febc2e' }} />
                <span style={{ background: '#28c840' }} />
              </div>
              <span className={styles.termTitle}>sandbox@honeyscan:~$</span>
              <span className={styles.termCount}>{logs.length} events</span>
            </div>
            <div className={styles.terminal}>
              {logs.length === 0 && (
                <div className={styles.termPlaceholder}>
                  {scanning ? '▌ Connecting to sandbox...' : '// Submit a URL to begin scanning'}
                </div>
              )}
              {logs.map((log) => (
                <div key={log.id} className={styles.logLine}>
                  <span className={styles.logTs}>{formatTime(log.timestamp)}</span>
                  <span className={styles.logLevel} style={{ color: LOG_COLORS[log.level] || 'var(--text-secondary)' }}>
                    [{log.level?.toUpperCase()}]
                  </span>
                  <span className={styles.logMsg} style={{ color: LOG_COLORS[log.level] || 'var(--text-secondary)' }}>
                    {log.message}
                  </span>
                </div>
              ))}
              <div ref={logsEndRef} />
            </div>
          </Card>

          {/* Network Requests */}
          <Card noPad>
            <div className={styles.netHeader}>
              <h2>Live Network Requests</h2>
              <span className={styles.netCount}>{netRequests.length} captured</span>
            </div>
            <div className={styles.netTableWrap}>
              <table className={styles.netTable}>
                <thead>
                  <tr>
                    <th>Method</th><th>URL</th><th>Status</th><th>Size</th><th>Flag</th>
                  </tr>
                </thead>
                <tbody>
                  {netRequests.length === 0 && (
                    <tr><td colSpan={5} className={styles.emptyCell}>No requests captured yet</td></tr>
                  )}
                  {netRequests.map((req, i) => (
                    <tr key={i} className={`${req.flagged ? styles.flaggedRow : ''}`}>
                      <td><span className={styles.method}>{req.method || '—'}</span></td>
                      <td className={styles.reqUrl}>{truncate(req.url, 55)}</td>
                      <td style={{ color: statusColor(req.status) }}>{req.status || '—'}</td>
                      <td className={styles.reqSize}>{formatSize(req.size)}</td>
                      <td>{req.flagged && <span className="material-symbols-rounded" style={{ fontSize: 16, color: 'var(--threat-red)' }}>flag</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}

const formatTime = (ts) => {
  try { return new Date(ts).toTimeString().slice(0,8); } catch { return '--:--:--'; }
};

const truncate = (s = '', n) => s.length > n ? s.slice(0,n)+'…' : s;

const statusColor = (s) => {
  if (!s) return 'var(--text-muted)';
  if (s < 300) return 'var(--safe-green)';
  if (s < 400) return 'var(--warn-amber)';
  return 'var(--threat-red)';
};

const formatSize = (b) => {
  if (!b) return '—';
  if (b < 1024) return `${b}B`;
  if (b < 1048576) return `${(b/1024).toFixed(1)}KB`;
  return `${(b/1048576).toFixed(1)}MB`;
};
