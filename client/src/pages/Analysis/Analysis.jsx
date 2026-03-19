import React, { useEffect, useState, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Cell, PieChart, Pie, ResponsiveContainer } from 'recharts';
import { SeverityBadge, Btn, Skeleton, EmptyState } from '../../components/ui/UIComponents';
import { useToast } from '../../context/ToastContext';
import api from '../../services/api';
import styles from './Analysis.module.scss';

const SIGNAL_LABELS = {
  scriptCount:      'Script Executions',
  redirectCount:    'Redirect Hops',
  hiddenIframes:    'Hidden iFrames',
  downloadAttempts: 'Download Attempts',
  domMutationRate:  'DOM Mutation Rate',
  externalScripts:  'External Scripts',
};

export default function Analysis() {
  const { scanId } = useParams();
  const navigate   = useNavigate();
  const { toast }  = useToast();

  const [scan, setScan]     = useState(null);
  const [dom, setDom]       = useState(null);
  const [loading, setLoading] = useState(true);
  const [iocSearch, setIocSearch] = useState('');
  const [iocSort, setIocSort]     = useState('confidence');
  const [vtLoading, setVtLoading] = useState({});

  useEffect(() => {
    fetchScan();
  }, [scanId]);

  const fetchScan = async () => {
    try {
      const { data } = await api.get(`/scans/${scanId}`);
      setScan(data.scan);
    } catch (e) {
      toast.error('Failed to load scan results');
      navigate('/history');
    } finally {
      setLoading(false);
    }
  };

  const fetchDom = async () => {
    if (dom) return;
    try {
      const { data } = await api.get(`/scans/${scanId}/dom`);
      setDom(data);
    } catch { toast.warn('DOM snapshots not available'); }
  };

  const handleVtLookup = async (iocId, value, type) => {
    setVtLoading(p => ({ ...p, [iocId]: true }));
    try {
      const { data } = await api.post(`/scans/${scanId}/ioc/${iocId}/virustotal`);
      setScan(p => ({
        ...p,
        iocs: p.iocs.map(i => i._id === iocId ? { ...i, ...data.ioc } : i),
      }));
      toast.success('VirusTotal lookup complete');
    } catch (e) {
      const msg = e.response?.data?.error || 'VT lookup failed';
      if (msg.includes('API key')) {
        toast.warn('Configure VirusTotal API key in Settings');
        // Fallback: open in browser
        const { getVirusTotalUrl } = await import('../../services/virusTotalService');
        window.open(getVirusTotalUrl?.(value, type) || `https://www.virustotal.com/gui/search/${encodeURIComponent(value)}`, '_blank');
      } else {
        toast.error(msg);
      }
    } finally {
      setVtLoading(p => ({ ...p, [iocId]: false }));
    }
  };

  const handleExport = async () => {
    window.open(`/api/scans/${scanId}/export`, '_blank');
  };

  if (loading) return <AnalysisSkeleton />;
  if (!scan) return null;

  const { scoreBreakdown = [], iocs = [], redirectChain = [], networkCapture } = scan;

  const filteredIocs = iocs
    .filter(i => !iocSearch || i.value?.toLowerCase().includes(iocSearch.toLowerCase()) || i.type?.includes(iocSearch))
    .sort((a, b) => iocSort === 'confidence' ? b.confidence - a.confidence : a.type?.localeCompare(b.type));

  const protocolData = networkCapture ? [
    { name: 'HTTP',  value: networkCapture.protocolBreakdown?.http   || 0, color: 'var(--accent-blue)'    },
    { name: 'HTTPS', value: networkCapture.protocolBreakdown?.https  || 0, color: 'var(--safe-green)'     },
    { name: 'DNS',   value: networkCapture.protocolBreakdown?.dns    || 0, color: 'var(--warn-amber)'     },
    { name: 'Other', value: networkCapture.protocolBreakdown?.other  || 0, color: 'var(--text-muted)'     },
  ].filter(d => d.value > 0) : [];

  return (
    <div className={styles.page}>
      {/* ── Sticky Header ── */}
      <div className={styles.stickyHeader}>
        <button className={styles.backBtn} onClick={() => navigate(-1)}>
          <span className="material-symbols-rounded">arrow_back</span>
        </button>
        <div className={styles.headerUrl}>
          <span className="material-symbols-rounded" style={{ color: 'var(--text-muted)', fontSize: 16 }}>link</span>
          <span className={styles.urlText}>{scan.url}</span>
        </div>
        <div className={styles.headerMeta}>
          <SeverityBadge level={scan.riskLevel} size="lg" />
          <span className={styles.timestamp}>{new Date(scan.submittedAt).toLocaleString()}</span>
        </div>
        <Btn variant="secondary" size="sm" icon="download" onClick={handleExport}>Export JSON</Btn>
      </div>

      <div className={styles.grid}>
        {/* ── Gauge + Recommended Action ── */}
        <div className={styles.gaugeSection}>
          <div className={styles.gaugeCard}>
            <ThreatGauge score={scan.threatScore} level={scan.riskLevel} />
          </div>
          <div className={styles.actionCard}>
            <div className={styles.actionHeader}>
              <span className="material-symbols-rounded">security</span>
              Recommended Action
            </div>
            <p className={styles.actionText}>{scan.recommendedAction}</p>
            <div className={styles.scanMeta}>
              <div className={styles.metaRow}><span>Scan Type</span><span className={styles.metaVal}>{scan.scanType}</span></div>
              <div className={styles.metaRow}><span>Duration</span><span className={styles.metaVal}>{scan.duration ? `${scan.duration}s` : '—'}</span></div>
              <div className={styles.metaRow}><span>IoCs Found</span><span className={styles.metaVal}>{iocs.length}</span></div>
              <div className={styles.metaRow}><span>Status</span><span className={`${styles.metaVal} ${styles.statusBadge}`}>{scan.status}</span></div>
            </div>
          </div>
        </div>

        {/* ── Signal Breakdown Bar Chart ── */}
        <div className={styles.signalSection}>
          <div className={styles.sectionHeader}>
            <span className="material-symbols-rounded">analytics</span>
            <h2>Behavioral Signal Breakdown</h2>
          </div>
          {scoreBreakdown.length === 0
            ? <EmptyState icon="analytics" title="No signal data" />
            : (
              <>
                <div className={styles.signalBars}>
                  {scoreBreakdown.map((sig, i) => (
                    <SignalRow key={sig.signal} sig={sig} delay={i * 60} />
                  ))}
                </div>
                <ResponsiveContainer width="100%" height={200} className={styles.signalChart}>
                  <BarChart data={scoreBreakdown} layout="vertical" margin={{ left: 10, right: 20, top: 4, bottom: 4 }}>
                    <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="var(--border)" />
                    <XAxis type="number" domain={[0, 1]} tick={{ fontSize: 10, fill: 'var(--text-muted)' }} tickLine={false} />
                    <YAxis type="category" dataKey="signal" tick={{ fontSize: 11, fill: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }} width={110} tickLine={false} tickFormatter={s => SIGNAL_LABELS[s] || s} />
                    <Tooltip formatter={(v, n) => [v.toFixed(4), n]} contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', fontSize: 11 }} />
                    <Bar dataKey="normalized" name="Normalized" radius={[0,2,2,0]} animationDuration={1000}>
                      {scoreBreakdown.map((entry, i) => (
                        <Cell key={i} fill={contribColor(entry.contribution)} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </>
            )
          }
        </div>

        {/* ── IoC Table ── */}
        <div className={styles.iocSection}>
          <div className={styles.sectionHeader}>
            <span className="material-symbols-rounded">bug_report</span>
            <h2>Indicators of Compromise ({filteredIocs.length})</h2>
            <div className={styles.iocControls}>
              <input className={styles.iocSearch} placeholder="Search IoCs…" value={iocSearch} onChange={e => setIocSearch(e.target.value)} />
              <select className={styles.iocSort} value={iocSort} onChange={e => setIocSort(e.target.value)}>
                <option value="confidence">Sort: Confidence</option>
                <option value="type">Sort: Type</option>
              </select>
            </div>
          </div>
          <IoCTable
            iocs={filteredIocs}
            vtLoading={vtLoading}
            onVtLookup={handleVtLookup}
          />
        </div>

        {/* ── Redirect Chain ── */}
        {redirectChain?.length > 0 && (
          <div className={styles.redirectSection}>
            <div className={styles.sectionHeader}>
              <span className="material-symbols-rounded">fork_right</span>
              <h2>Redirect Chain ({redirectChain.length} hops)</h2>
            </div>
            <RedirectChainDiagram chain={redirectChain} />
          </div>
        )}

        {/* ── Network Capture ── */}
        {networkCapture && (
          <div className={styles.networkSection}>
            <div className={styles.sectionHeader}>
              <span className="material-symbols-rounded">network_check</span>
              <h2>Packet Analysis</h2>
              {networkCapture.pcapPath && (
                <a href={`/captures/${networkCapture.pcapPath.split('/').pop()}`} download className={styles.pcapBtn}>
                  <span className="material-symbols-rounded">download</span> .pcap
                </a>
              )}
            </div>
            <div className={styles.netStats}>
              <div className={styles.netStat}><span>Total Packets</span><b>{networkCapture.totalPackets}</b></div>
              <div className={styles.netStat}><span>Suspicious</span><b style={{ color: 'var(--threat-red)' }}>{networkCapture.suspiciousPackets}</b></div>
              <div className={styles.netStat}><span>Suricata Alerts</span><b style={{ color: 'var(--warn-amber)' }}>{networkCapture.suricataAlerts?.length || 0}</b></div>
            </div>
            {protocolData.length > 0 && (
              <ResponsiveContainer width="100%" height={160}>
                <PieChart>
                  <Pie data={protocolData} cx="50%" cy="50%" outerRadius={60} dataKey="value" animationDuration={800}>
                    {protocolData.map((d, i) => <Cell key={i} fill={d.color} stroke="transparent" />)}
                  </Pie>
                  <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', fontSize: 11 }} />
                </PieChart>
              </ResponsiveContainer>
            )}
            {networkCapture.suricataAlerts?.length > 0 && (
              <SuricataTable alerts={networkCapture.suricataAlerts} />
            )}
          </div>
        )}

        {/* ── DOM Snapshot Diff ── */}
        <div className={styles.domSection}>
          <div className={styles.sectionHeader}>
            <span className="material-symbols-rounded">code</span>
            <h2>DOM Snapshot Diff</h2>
            <Btn variant="ghost" size="sm" icon="compare" onClick={fetchDom}>Load Snapshots</Btn>
          </div>
          {dom
            ? <DomDiff before={dom.before} after={dom.after} />
            : <div className={styles.domPlaceholder}>Click "Load Snapshots" to compare before/after DOM states</div>
          }
        </div>
      </div>
    </div>
  );
}

/* ── Threat Gauge SVG ── */
function ThreatGauge({ score = 0, level }) {
  const [displayed, setDisplayed] = useState(0);
  const RADIUS = 80; const CX = 110; const CY = 100;
  const START_ANGLE = -200; const END_ANGLE = 20;
  const totalArc = END_ANGLE - START_ANGLE;

  const toRad = (deg) => (deg * Math.PI) / 180;
  const arcPath = (startDeg, endDeg, r) => {
    const s = toRad(startDeg), e = toRad(endDeg);
    const x1 = CX + r * Math.cos(s), y1 = CY + r * Math.sin(s);
    const x2 = CX + r * Math.cos(e), y2 = CY + r * Math.sin(e);
    const large = endDeg - startDeg > 180 ? 1 : 0;
    return `M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2}`;
  };

  useEffect(() => {
    let frame;
    const start = performance.now();
    const animate = (now) => {
      const p = Math.min((now - start) / 1500, 1);
      const ease = 1 - Math.pow(1 - p, 3);
      setDisplayed(Math.round(score * ease));
      if (p < 1) frame = requestAnimationFrame(animate);
    };
    frame = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(frame);
  }, [score]);

  const needleAngle = START_ANGLE + (score / 100) * totalArc;
  const nx = CX + (RADIUS - 10) * Math.cos(toRad(needleAngle));
  const ny = CY + (RADIUS - 10) * Math.sin(toRad(needleAngle));

  const COLORS = [
    { start: 0, end: 25,  color: 'var(--safe-green)' },
    { start: 25, end: 50, color: 'var(--warn-amber)' },
    { start: 50, end: 75, color: 'var(--score-high)' },
    { start: 75, end: 100,color: 'var(--threat-red)' },
  ];

  return (
    <div className={styles.gaugeWrap}>
      <svg width="220" height="140" viewBox="0 0 220 140">
        <defs>
          <linearGradient id="gaugeGrad" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%"   stopColor="var(--safe-green)" />
            <stop offset="33%"  stopColor="var(--warn-amber)" />
            <stop offset="66%"  stopColor="var(--score-high)" />
            <stop offset="100%" stopColor="var(--threat-red)" />
          </linearGradient>
        </defs>
        {/* Background arc */}
        <path d={arcPath(START_ANGLE, END_ANGLE, RADIUS)} fill="none" stroke="var(--border)" strokeWidth="12" strokeLinecap="round" />
        {/* Colored fill arc */}
        {score > 0 && (
          <path
            d={arcPath(START_ANGLE, START_ANGLE + (score / 100) * totalArc, RADIUS)}
            fill="none" stroke="url(#gaugeGrad)" strokeWidth="12" strokeLinecap="round"
          />
        )}
        {/* Needle */}
        <line x1={CX} y1={CY} x2={nx} y2={ny} stroke="var(--text-primary)" strokeWidth="2.5" strokeLinecap="round"
          style={{ transition: 'x2 1.5s cubic-bezier(0.34,1.56,0.64,1), y2 1.5s cubic-bezier(0.34,1.56,0.64,1)' }} />
        <circle cx={CX} cy={CY} r="5" fill="var(--text-primary)" />
        {/* Score labels */}
        <text x="22"  y="118" fontSize="9" fill="var(--text-muted)" fontFamily="var(--font-mono)">0</text>
        <text x="96"  y="28"  fontSize="9" fill="var(--text-muted)" fontFamily="var(--font-mono)">50</text>
        <text x="188" y="118" fontSize="9" fill="var(--text-muted)" fontFamily="var(--font-mono)">100</text>
      </svg>
      <div className={styles.gaugeScore} style={{ color: scoreColor(score) }}>{displayed}</div>
      <div className={styles.gaugeLabel}>Threat Score</div>
    </div>
  );
}

/* ── Signal Row ── */
function SignalRow({ sig, delay }) {
  return (
    <div className={styles.sigRow} style={{ animationDelay: `${delay}ms` }}>
      <span className={styles.sigName}>{SIGNAL_LABELS[sig.signal] || sig.signal}</span>
      <div className={styles.sigBar}>
        <div
          className={styles.sigFill}
          style={{
            '--bar-width': `${sig.normalized * 100}%`,
            background: contribColor(sig.contribution),
            animationDelay: `${delay}ms`,
          }}
        />
      </div>
      <div className={styles.sigNums}>
        <span title="Raw value" className={styles.rawVal}>{sig.rawValue}</span>
        <span title="Contribution" className={styles.contribVal} style={{ color: contribColor(sig.contribution) }}>
          +{(sig.contribution * 100).toFixed(1)}
        </span>
      </div>
    </div>
  );
}

/* ── IoC Table ── */
function IoCTable({ iocs, vtLoading, onVtLookup }) {
  const copy = (v) => { navigator.clipboard.writeText(v); };
  if (iocs.length === 0) return <EmptyState icon="bug_report" title="No IoCs extracted" message="No indicators of compromise were identified in this scan" />;
  return (
    <div className={styles.iocTableWrap}>
      <table className={styles.iocTable}>
        <thead>
          <tr><th>Type</th><th>Value</th><th>Confidence</th><th>VT</th><th>First Seen</th><th>Actions</th></tr>
        </thead>
        <tbody>
          {iocs.map((ioc) => (
            <tr key={ioc._id}>
              <td><span className={styles.iocType}>{ioc.type}</span></td>
              <td><code className={styles.iocValue}>{ioc.value}</code></td>
              <td>
                <div className={styles.confBar}>
                  <div className={styles.confFill} style={{ width: `${ioc.confidence}%`, background: confColor(ioc.confidence) }} />
                  <span>{ioc.confidence}%</span>
                </div>
              </td>
              <td>
                {ioc.virusTotalResult
                  ? <span className={styles.vtResult} style={{ color: ioc.virusTotalResult.positives > 0 ? 'var(--threat-red)' : 'var(--safe-green)' }}>
                      {ioc.virusTotalResult.positives}/{ioc.virusTotalResult.total}
                    </span>
                  : '—'
                }
              </td>
              <td className={styles.monoSm}>{new Date(ioc.firstSeen).toLocaleDateString()}</td>
              <td>
                <div className={styles.iocActions}>
                  <button className={styles.iocBtn} onClick={() => copy(ioc.value)} title="Copy">
                    <span className="material-symbols-rounded">content_copy</span>
                  </button>
                  <button
                    className={`${styles.iocBtn} ${styles.vtBtn}`}
                    onClick={() => onVtLookup(ioc._id, ioc.value, ioc.type)}
                    disabled={vtLoading[ioc._id]}
                    title="VirusTotal Lookup"
                  >
                    {vtLoading[ioc._id]
                      ? <span className="material-symbols-rounded" style={{ animation: 'spinLoader 0.8s linear infinite' }}>progress_activity</span>
                      : <span className="material-symbols-rounded">search</span>
                    }
                  </button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* ── Redirect Chain Diagram ── */
function RedirectChainDiagram({ chain }) {
  const repColor = (r) => ({
    safe: 'var(--safe-green)', suspicious: 'var(--warn-amber)',
    malicious: 'var(--threat-red)', unknown: 'var(--text-muted)',
  })[r] || 'var(--text-muted)';

  return (
    <div className={styles.redirectChain}>
      {chain.map((hop, i) => (
        <React.Fragment key={i}>
          <div className={styles.redirectNode} style={{ borderColor: repColor(hop.reputation) }}>
            <span className={styles.nodeReputation} style={{ color: repColor(hop.reputation) }}>
              {hop.reputation || 'unknown'}
            </span>
            <code className={styles.nodeUrl}>{truncateUrl(hop.to || hop.from)}</code>
            <span className={styles.nodeStatus} style={{ color: statusColor(hop.status) }}>
              {hop.status || '—'}
            </span>
          </div>
          {i < chain.length - 1 && (
            <div className={styles.redirectArrow}>
              <span className="material-symbols-rounded">arrow_forward</span>
            </div>
          )}
        </React.Fragment>
      ))}
    </div>
  );
}

/* ── Suricata Table ── */
function SuricataTable({ alerts }) {
  return (
    <div className={styles.suricataWrap}>
      <div className={styles.suricataTitle}>Suricata IDS Alerts ({alerts.length})</div>
      <table className={styles.iocTable}>
        <thead>
          <tr><th>Severity</th><th>Signature</th><th>Category</th><th>Src IP</th><th>Dst IP</th></tr>
        </thead>
        <tbody>
          {alerts.map((a, i) => (
            <tr key={i}>
              <td><span style={{ color: a.severity === 1 ? 'var(--threat-red)' : a.severity === 2 ? 'var(--warn-amber)' : 'var(--text-muted)' }}>
                {['', 'HIGH', 'MED', 'LOW'][a.severity] || '?'}</span></td>
              <td className={styles.monoSm}>{a.signature}</td>
              <td>{a.category}</td>
              <td className={styles.monoSm}>{a.srcIp}</td>
              <td className={styles.monoSm}>{a.destIp}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* ── DOM Diff ── */
function DomDiff({ before, after }) {
  return (
    <div className={styles.domDiff}>
      <div className={styles.domPane}>
        <div className={styles.domPaneLabel}>Before Script Execution</div>
        <pre className={styles.domCode}>{before?.slice(0, 4000)}</pre>
      </div>
      <div className={styles.domPane}>
        <div className={styles.domPaneLabel}>After Observation Window</div>
        <pre className={styles.domCode}>{after?.slice(0, 4000)}</pre>
      </div>
    </div>
  );
}

/* ── Analysis Skeleton ── */
function AnalysisSkeleton() {
  return (
    <div style={{ padding: 32 }}>
      {[1,2,3,4].map(i => (
        <div key={i} style={{ marginBottom: 20, height: 120, background: 'var(--bg-card)', borderRadius: 2, animation: 'shimmer 1.5s infinite' }} />
      ))}
    </div>
  );
}

/* ── Utilities ── */
const scoreColor = (s) => {
  if (s < 26) return 'var(--safe-green)';
  if (s < 51) return 'var(--warn-amber)';
  if (s < 76) return 'var(--score-high)';
  return 'var(--threat-red)';
};
const contribColor = (c) => {
  if (c < 0.05) return 'var(--safe-green)';
  if (c < 0.10) return 'var(--warn-amber)';
  if (c < 0.15) return 'var(--score-high)';
  return 'var(--threat-red)';
};
const confColor = (c) => {
  if (c < 40)  return 'var(--safe-green)';
  if (c < 70)  return 'var(--warn-amber)';
  return 'var(--threat-red)';
};
const statusColor = (s) => {
  if (!s) return 'var(--text-muted)';
  if (s < 300) return 'var(--safe-green)';
  if (s < 400) return 'var(--warn-amber)';
  return 'var(--threat-red)';
};
const truncateUrl = (u = '', n = 35) => u.length > n ? u.slice(0, n) + '…' : u;
