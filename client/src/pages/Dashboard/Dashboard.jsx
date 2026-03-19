import React, { useEffect, useState, useCallback, useRef } from 'react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
} from 'recharts';
import { PageHeader, StatCard, Card, SeverityBadge, EmptyState } from '../../components/ui/UIComponents';
import { getSocket, subscribeScan } from '../../services/socket';
import api from '../../services/api';
import styles from './Dashboard.module.scss';

const SEVERITY_COLORS = {
  Safe:     'var(--safe-green)',
  Medium:   'var(--warn-amber)',
  High:     'var(--threat-red)',
  Critical: 'var(--critical-purple)',
};

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className={styles.tooltip}>
      <div className={styles.tooltipLabel}>{label}</div>
      {payload.map((p, i) => (
        <div key={i} className={styles.tooltipRow} style={{ color: p.color }}>
          <span>{p.name}</span><span>{p.value}</span>
        </div>
      ))}
    </div>
  );
};

export default function Dashboard() {
  const [overview, setOverview]     = useState(null);
  const [scansPerDay, setScansPerDay] = useState([]);
  const [severity, setSeverity]     = useState([]);
  const [heatmap, setHeatmap]       = useState([]);
  const [recent, setRecent]         = useState([]);
  const [loading, setLoading]       = useState(true);
  const feedRef = useRef(null);

  const fetchAll = useCallback(async () => {
    try {
      const [ov, spd, sev, hm, rec] = await Promise.all([
        api.get('/stats/overview'),
        api.get('/stats/scans-per-day'),
        api.get('/stats/severity-distribution'),
        api.get('/stats/heatmap'),
        api.get('/scans/recent'),
      ]);
      setOverview(ov.data);
      setScansPerDay(spd.data.data || []);
      setSeverity(sev.data.data.map(d => ({ name: d._id || 'Unknown', value: d.count })));
      setHeatmap(hm.data.data || []);
      setRecent(rec.data.scans || []);
    } catch (e) {
      console.error('Dashboard fetch error:', e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
    const interval = setInterval(fetchAll, 30000);
    return () => clearInterval(interval);
  }, [fetchAll]);

  // Live feed via Socket.IO
  useEffect(() => {
    const socket = getSocket();
    const onComplete = (data) => {
      setRecent(prev => {
        const updated = [{ ...data, submittedAt: new Date() }, ...prev].slice(0, 12);
        return updated;
      });
      fetchAll(); // refresh stats
    };
    socket.on('scan:complete', onComplete);
    return () => socket.off('scan:complete', onComplete);
  }, [fetchAll]);

  // Build heatmap grid: 7 days × 24 hours
  const heatmapGrid = buildHeatmapGrid(heatmap);

  const areaData = buildAreaData(scansPerDay);

  return (
    <div className={styles.page}>
      <PageHeader
        title="Threat Dashboard"
        subtitle="Real-time overview of your honeypot scan intelligence"
        icon="radar"
        actions={
          <button className={styles.refreshBtn} onClick={fetchAll}>
            <span className="material-symbols-rounded">refresh</span>
            Refresh
          </button>
        }
      />

      {/* ── Stat Cards ── */}
      <div className={styles.statGrid}>
        <StatCard label="Total Scans"      value={overview?.totalScans}      icon="analytics"   color="blue"   loading={loading} />
        <StatCard label="Critical Threats" value={overview?.criticalThreats} icon="gpp_bad"     color="red"    loading={loading} />
        <StatCard label="Avg Threat Score" value={overview?.avgThreatScore}  icon="shield"      color="amber"  loading={loading} />
        <StatCard label="IoCs Discovered"  value={overview?.iocsDiscovered}  icon="bug_report"  color="purple" loading={loading} />
      </div>

      {/* ── Charts row ── */}
      <div className={styles.chartsRow}>
        {/* Area chart */}
        <Card className={styles.areaCard}>
          <div className={styles.cardHeader}>
            <h2>Scans per Day</h2>
            <span className={styles.cardSub}>Last 30 days — total vs high+critical</span>
          </div>
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={areaData} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="colorTotal" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="var(--accent-blue)"  stopOpacity={0.35} />
                  <stop offset="95%" stopColor="var(--accent-blue)"  stopOpacity={0.02} />
                </linearGradient>
                <linearGradient id="colorHigh" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="var(--threat-red)"  stopOpacity={0.35} />
                  <stop offset="95%" stopColor="var(--threat-red)"  stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
              <XAxis dataKey="date" tick={{ fontSize: 11, fill: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }} tickLine={false} axisLine={false} />
              <YAxis tick={{ fontSize: 11, fill: 'var(--text-muted)' }} tickLine={false} axisLine={false} allowDecimals={false} />
              <Tooltip content={<CustomTooltip />} />
              <Area type="monotone" dataKey="total"       name="Total"        stroke="var(--accent-blue)" fill="url(#colorTotal)" strokeWidth={2} dot={false} />
              <Area type="monotone" dataKey="highCritical" name="High+Critical" stroke="var(--threat-red)"  fill="url(#colorHigh)"  strokeWidth={2} dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        </Card>

        {/* Severity Donut */}
        <Card className={styles.donutCard}>
          <div className={styles.cardHeader}>
            <h2>Severity Distribution</h2>
          </div>
          {severity.length === 0 && !loading
            ? <EmptyState icon="donut_large" title="No data yet" message="Complete scans will appear here" />
            : (
              <ResponsiveContainer width="100%" height={220}>
                <PieChart>
                  <Pie
                    data={severity}
                    cx="50%" cy="50%"
                    innerRadius={60} outerRadius={90}
                    paddingAngle={3}
                    dataKey="value"
                    animationBegin={0}
                    animationDuration={1000}
                  >
                    {severity.map((entry, i) => (
                      <Cell key={i} fill={SEVERITY_COLORS[entry.name] || 'var(--text-muted)'} stroke="transparent" />
                    ))}
                  </Pie>
                  <Tooltip formatter={(v, n) => [v, n]} contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 3, fontFamily: 'var(--font-body)', fontSize: 12 }} />
                  <Legend
                    formatter={(v) => <span style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-body)', fontSize: 12 }}>{v}</span>}
                    iconType="circle"
                    iconSize={8}
                  />
                </PieChart>
              </ResponsiveContainer>
            )
          }
        </Card>
      </div>

      {/* ── Heatmap + Live Feed ── */}
      <div className={styles.bottomRow}>
        {/* 7×24 Heatmap */}
        <Card className={styles.heatmapCard}>
          <div className={styles.cardHeader}>
            <h2>Activity Heatmap</h2>
            <span className={styles.cardSub}>Avg threat score by day × hour (last 7 days)</span>
          </div>
          <HeatmapGrid grid={heatmapGrid} />
        </Card>

        {/* Live Recent Scans Feed */}
        <Card className={styles.feedCard}>
          <div className={styles.cardHeader}>
            <h2>Recent Scans</h2>
            <span className={`${styles.liveIndicator}`}>
              <span className={styles.liveDot} />LIVE
            </span>
          </div>
          <div className={styles.feedList} ref={feedRef}>
            {recent.length === 0 && !loading
              ? <EmptyState icon="history" title="No scans yet" message="Submit URLs in the Scanner" />
              : recent.map((scan, i) => (
                <RecentScanRow key={scan._id || i} scan={scan} />
              ))
            }
          </div>
        </Card>
      </div>
    </div>
  );
}

/* ── Helper: Recent Scan Row ── */
function RecentScanRow({ scan }) {
  const navigate = (id) => window.location.href = `/analysis/${id}`;
  return (
    <div className={`${styles.feedRow} anim-slide-right`} onClick={() => scan._id && navigate(scan._id)}>
      <div className={styles.feedUrl}>
        <span className="material-symbols-rounded" style={{ fontSize: 16, color: 'var(--text-muted)' }}>link</span>
        <span className={styles.feedUrlText}>{truncate(scan.url, 40)}</span>
      </div>
      <div className={styles.feedMeta}>
        <SeverityBadge level={scan.riskLevel} size="sm" pulse={false} />
        {scan.threatScore !== undefined && (
          <span className={styles.feedScore} style={{ color: scoreColor(scan.threatScore) }}>
            {scan.threatScore}
          </span>
        )}
        <span className={styles.feedTime}>{timeAgo(scan.submittedAt)}</span>
      </div>
    </div>
  );
}

/* ── Heatmap Grid ── */
const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const HOURS = Array.from({ length: 24 }, (_, i) => i);

function HeatmapGrid({ grid }) {
  return (
    <div className={styles.heatmap}>
      <div className={styles.heatmapAxis}>
        {DAYS.map(d => <span key={d}>{d}</span>)}
      </div>
      <div className={styles.heatmapBody}>
        {HOURS.map(h => (
          <div key={h} className={styles.heatmapRow}>
            <span className={styles.heatmapHour}>{h.toString().padStart(2,'0')}</span>
            {DAYS.map((_, day) => {
              const val = grid[day]?.[h] ?? 0;
              const intensity = val / 100;
              return (
                <div
                  key={day}
                  className={styles.heatmapCell}
                  title={`${DAYS[day]} ${h}:00 — avg score: ${Math.round(val)}`}
                  style={{
                    background: val === 0
                      ? 'var(--bg-base)'
                      : `rgba(${scoreRGB(val)}, ${Math.max(0.15, intensity)})`,
                    border: '1px solid var(--border)',
                  }}
                />
              );
            })}
          </div>
        ))}
      </div>
      <div className={styles.heatmapLegend}>
        <span>Low</span>
        <div className={styles.legendGradient} />
        <span>Critical</span>
      </div>
    </div>
  );
}

/* ── Utilities ── */
function buildAreaData(raw) {
  const today = new Date();
  const days = Array.from({ length: 30 }, (_, i) => {
    const d = new Date(today);
    d.setDate(d.getDate() - (29 - i));
    return d.toISOString().slice(0, 10);
  });
  const map = {};
  raw.forEach(r => { map[r._id] = r; });
  return days.map(date => ({
    date: date.slice(5),
    total: map[date]?.total || 0,
    highCritical: map[date]?.highCritical || 0,
  }));
}

function buildHeatmapGrid(data) {
  const grid = Array.from({ length: 7 }, () => Array(24).fill(0));
  data.forEach(({ _id, avgScore }) => {
    const day = (_id.dayOfWeek - 1 + 7) % 7;
    const hour = _id.hour;
    if (day >= 0 && day < 7 && hour >= 0 && hour < 24) {
      grid[day][hour] = avgScore || 0;
    }
  });
  return grid;
}

function scoreRGB(score) {
  if (score < 26)  return '79,249,168';
  if (score < 51)  return '249,168,79';
  if (score < 76)  return '249,120,79';
  return '249,79,109';
}

function scoreColor(score) {
  if (score < 26)  return 'var(--safe-green)';
  if (score < 51)  return 'var(--warn-amber)';
  if (score < 76)  return 'var(--score-high)';
  return 'var(--threat-red)';
}

function truncate(str = '', max) {
  return str.length <= max ? str : str.slice(0, max) + '…';
}

function timeAgo(date) {
  if (!date) return '';
  const secs = Math.floor((Date.now() - new Date(date)) / 1000);
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs/60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs/3600)}h ago`;
  return `${Math.floor(secs/86400)}d ago`;
}
