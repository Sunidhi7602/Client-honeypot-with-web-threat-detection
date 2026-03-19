import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { PageHeader, SeverityBadge, SearchInput, Btn, EmptyState } from '../../components/ui/UIComponents';
import { useToast } from '../../context/ToastContext';
import api from '../../services/api';
import styles from './History.module.scss';

const RISK_LEVELS = ['', 'Safe', 'Medium', 'High', 'Critical'];
const PAGE_SIZE = 20;

export default function History() {
  const navigate = useNavigate();
  const { toast } = useToast();

  const [scans, setScans]         = useState([]);
  const [total, setTotal]         = useState(0);
  const [page, setPage]           = useState(1);
  const [loading, setLoading]     = useState(true);
  const [search, setSearch]       = useState('');
  const [riskFilter, setRiskFilter] = useState('');
  const [sortBy, setSortBy]       = useState('submittedAt');
  const [sortOrder, setSortOrder] = useState('desc');
  const [selected, setSelected]   = useState(new Set());

  const fetchScans = useCallback(async () => {
    setLoading(true);
    try {
      const { data } = await api.get('/scans', {
        params: { page, limit: PAGE_SIZE, search, riskLevel: riskFilter, sortBy, sortOrder },
      });
      setScans(data.scans);
      setTotal(data.pagination.total);
    } catch {
      toast.error('Failed to load scan history');
    } finally {
      setLoading(false);
    }
  }, [page, search, riskFilter, sortBy, sortOrder]);

  useEffect(() => { fetchScans(); }, [fetchScans]);

  // Reset page on filter change
  useEffect(() => { setPage(1); }, [search, riskFilter]);

  const toggleSelect = (id) => {
    setSelected(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const toggleAll = () => {
    if (selected.size === scans.length) setSelected(new Set());
    else setSelected(new Set(scans.map(s => s._id)));
  };

  const handleDelete = async (id) => {
    if (!confirm('Delete this scan?')) return;
    try {
      await api.delete(`/scans/${id}`);
      toast.success('Scan deleted');
      fetchScans();
    } catch { toast.error('Failed to delete scan'); }
  };

  const handleBulkDelete = async () => {
    if (!selected.size) return;
    if (!confirm(`Delete ${selected.size} scan(s)?`)) return;
    try {
      await api.post('/scans/bulk-delete', { ids: Array.from(selected) });
      toast.success(`Deleted ${selected.size} scans`);
      setSelected(new Set());
      fetchScans();
    } catch { toast.error('Bulk delete failed'); }
  };

  const handleExportCsv = async () => {
    const ids = selected.size ? Array.from(selected) : [];
    const resp = await api.post('/scans/export-csv', { ids }, { responseType: 'blob' });
    const url = URL.createObjectURL(resp.data);
    const a = document.createElement('a');
    a.href = url; a.download = 'honeyscan-export.csv'; a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportJson = async () => {
    const ids = selected.size ? Array.from(selected) : [];
    if (ids.length === 1) { window.open(`/api/scans/${ids[0]}/export`, '_blank'); return; }
    toast.info('Select a single scan to export as JSON, or use CSV for bulk export');
  };

  const sortHeader = (field) => {
    if (sortBy === field) setSortOrder(o => o === 'asc' ? 'desc' : 'asc');
    else { setSortBy(field); setSortOrder('desc'); }
  };

  const SortIcon = ({ field }) => {
    if (sortBy !== field) return <span className="material-symbols-rounded" style={{ fontSize: 14, opacity: 0.3 }}>unfold_more</span>;
    return <span className="material-symbols-rounded" style={{ fontSize: 14, color: 'var(--accent-blue)' }}>
      {sortOrder === 'asc' ? 'expand_less' : 'expand_more'}
    </span>;
  };

  const totalPages = Math.ceil(total / PAGE_SIZE);

  return (
    <div className={styles.page}>
      <PageHeader
        title="Scan History"
        subtitle={`${total} total scans`}
        icon="history"
        actions={
          <div className={styles.headerActions}>
            {selected.size > 0 && (
              <>
                <Btn variant="ghost" size="sm" icon="file_download" onClick={handleExportCsv}>CSV</Btn>
                <Btn variant="ghost" size="sm" icon="data_object" onClick={handleExportJson}>JSON</Btn>
                <Btn variant="danger" size="sm" icon="delete" onClick={handleBulkDelete}>{selected.size} selected</Btn>
              </>
            )}
          </div>
        }
      />

      {/* Filters */}
      <div className={styles.filters}>
        <SearchInput
          value={search}
          onChange={(v) => setSearch(v)}
          placeholder="Search by URL…"
          className={styles.searchInput}
        />
        <select
          className={styles.filterSelect}
          value={riskFilter}
          onChange={e => setRiskFilter(e.target.value)}
        >
          {RISK_LEVELS.map(l => (
            <option key={l} value={l}>{l || 'All Severities'}</option>
          ))}
        </select>
      </div>

      {/* Table */}
      <div className={styles.tableWrap}>
        <table className={styles.table}>
          <thead>
            <tr>
              <th className={styles.checkTh}>
                <input type="checkbox"
                  checked={scans.length > 0 && selected.size === scans.length}
                  onChange={toggleAll}
                />
              </th>
              <th onClick={() => sortHeader('url')} className={styles.sortable}>URL <SortIcon field="url" /></th>
              <th onClick={() => sortHeader('submittedAt')} className={styles.sortable}>Scanned <SortIcon field="submittedAt" /></th>
              <th onClick={() => sortHeader('threatScore')} className={styles.sortable}>Score <SortIcon field="threatScore" /></th>
              <th>Severity</th>
              <th onClick={() => sortHeader('status')} className={styles.sortable}>Status <SortIcon field="status" /></th>
              <th>IoCs</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading && Array.from({ length: 6 }).map((_, i) => (
              <tr key={i}>
                {Array.from({ length: 8 }).map((_, j) => (
                  <td key={j}><div className={styles.skeletonCell} /></td>
                ))}
              </tr>
            ))}
            {!loading && scans.length === 0 && (
              <tr>
                <td colSpan={8}>
                  <EmptyState icon="history" title="No scans found" message="Adjust your filters or submit a new URL in the Scanner" />
                </td>
              </tr>
            )}
            {!loading && scans.map((scan) => (
              <tr
                key={scan._id}
                className={`${styles.row} ${selected.has(scan._id) ? styles.selectedRow : ''}`}
              >
                <td className={styles.checkCell}>
                  <input type="checkbox"
                    checked={selected.has(scan._id)}
                    onChange={() => toggleSelect(scan._id)}
                    onClick={e => e.stopPropagation()}
                  />
                </td>
                <td className={styles.urlCell} onClick={() => navigate(`/analysis/${scan._id}`)}>
                  <span className="material-symbols-rounded" style={{ fontSize: 14, color: 'var(--text-muted)' }}>link</span>
                  <span className={styles.urlText}>{scan.url}</span>
                </td>
                <td className={styles.mono}>{new Date(scan.submittedAt).toLocaleString()}</td>
                <td>
                  {scan.threatScore !== undefined
                    ? <span className={styles.scoreVal} style={{ color: scoreColor(scan.threatScore) }}>{scan.threatScore}</span>
                    : <span className={styles.dash}>—</span>
                  }
                </td>
                <td><SeverityBadge level={scan.riskLevel} size="sm" /></td>
                <td>
                  <span className={`${styles.statusPill} ${styles[`status_${scan.status}`]}`}>
                    {scan.status === 'scanning' && <span className={styles.scanning} />}
                    {scan.status}
                  </span>
                </td>
                <td className={styles.mono}>{scan.iocs?.length ?? '—'}</td>
                <td>
                  <div className={styles.actions}>
                    <button className={styles.actionBtn} onClick={() => navigate(`/analysis/${scan._id}`)} title="View">
                      <span className="material-symbols-rounded">visibility</span>
                    </button>
                    <button className={styles.actionBtn} onClick={() => window.open(`/api/scans/${scan._id}/export`, '_blank')} title="Export">
                      <span className="material-symbols-rounded">download</span>
                    </button>
                    <button className={`${styles.actionBtn} ${styles.deleteBtn}`} onClick={() => handleDelete(scan._id)} title="Delete">
                      <span className="material-symbols-rounded">delete</span>
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className={styles.pagination}>
          <span className={styles.pageInfo}>
            Showing {((page - 1) * PAGE_SIZE) + 1}–{Math.min(page * PAGE_SIZE, total)} of {total}
          </span>
          <div className={styles.pageControls}>
            <button className={styles.pageBtn} disabled={page === 1} onClick={() => setPage(1)}>
              <span className="material-symbols-rounded">first_page</span>
            </button>
            <button className={styles.pageBtn} disabled={page === 1} onClick={() => setPage(p => p - 1)}>
              <span className="material-symbols-rounded">chevron_left</span>
            </button>
            {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
              const p = Math.max(1, Math.min(page - 2, totalPages - 4)) + i;
              return (
                <button key={p} className={`${styles.pageBtn} ${p === page ? styles.activePage : ''}`} onClick={() => setPage(p)}>
                  {p}
                </button>
              );
            })}
            <button className={styles.pageBtn} disabled={page === totalPages} onClick={() => setPage(p => p + 1)}>
              <span className="material-symbols-rounded">chevron_right</span>
            </button>
            <button className={styles.pageBtn} disabled={page === totalPages} onClick={() => setPage(totalPages)}>
              <span className="material-symbols-rounded">last_page</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

const scoreColor = (s) => {
  if (s < 26) return 'var(--safe-green)';
  if (s < 51) return 'var(--warn-amber)';
  if (s < 76) return '#f9784f';
  return 'var(--threat-red)';
};
