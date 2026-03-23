import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { PageHeader, SeverityBadge, SearchInput, EmptyState } from '../../components/ui/UIComponents';
import { useToast } from '../../context/ToastContext';
import api from '../../services/api';
import styles from './History.module.scss';

const RISK_LEVELS = ['', 'Safe', 'Medium', 'High', 'Critical'];
const PAGE_SIZE = 20;

export default function History() {
  const navigate = useNavigate();
  const { toast } = useToast();

  const [scans, setScans] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [riskFilter, setRiskFilter] = useState('');
  const [sortBy, setSortBy] = useState('submittedAt');
  const [sortOrder, setSortOrder] = useState('desc');

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
  }, [page, search, riskFilter, sortBy, sortOrder, toast]);

  useEffect(() => {
    fetchScans();
  }, [fetchScans]);

  useEffect(() => {
    setPage(1);
  }, [search, riskFilter]);

  const handleDelete = async (id) => {
    if (!confirm('Delete this scan?')) return;
    try {
      await api.delete(`/scans/${id}`);
      toast.success('Scan deleted');
      fetchScans();
    } catch {
      toast.error('Failed to delete scan');
    }
  };

  const sortHeader = (field) => {
    if (sortBy === field) setSortOrder((order) => (order === 'asc' ? 'desc' : 'asc'));
    else {
      setSortBy(field);
      setSortOrder('desc');
    }
  };

  const SortIcon = ({ field }) => {
    if (sortBy !== field) {
      return (
        <span className="material-symbols-rounded" style={{ fontSize: 14, opacity: 0.3 }}>
          unfold_more
        </span>
      );
    }

    return (
      <span className="material-symbols-rounded" style={{ fontSize: 14, color: 'var(--accent-blue)' }}>
        {sortOrder === 'asc' ? 'expand_less' : 'expand_more'}
      </span>
    );
  };

  const totalPages = Math.ceil(total / PAGE_SIZE);

  return (
    <div className={styles.page}>
      <PageHeader title="Scan History" subtitle={`${total} total scans`} icon="history" />

      <div className={styles.filters}>
        <SearchInput
          value={search}
          onChange={(value) => setSearch(value)}
          placeholder="Search by URL..."
          className={styles.searchInput}
        />
        <select
          className={styles.filterSelect}
          value={riskFilter}
          onChange={(e) => setRiskFilter(e.target.value)}
        >
          {RISK_LEVELS.map((level) => (
            <option key={level} value={level}>
              {level || 'All Severities'}
            </option>
          ))}
        </select>
      </div>

      <div className={styles.tableWrap}>
        <table className={styles.table}>
          <thead>
            <tr>
              <th onClick={() => sortHeader('url')} className={styles.sortable}>
                <span className={styles.sortLabel}>
                  URL <SortIcon field="url" />
                </span>
              </th>
              <th onClick={() => sortHeader('submittedAt')} className={styles.sortable}>
                <span className={styles.sortLabel}>
                  Scanned <SortIcon field="submittedAt" />
                </span>
              </th>
              <th onClick={() => sortHeader('threatScore')} className={styles.sortable}>
                <span className={styles.sortLabel}>
                  Score <SortIcon field="threatScore" />
                </span>
              </th>
              <th>Severity</th>
              <th onClick={() => sortHeader('status')} className={styles.sortable}>
                <span className={styles.sortLabel}>
                  Status <SortIcon field="status" />
                </span>
              </th>
              <th>IoCs</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading &&
              Array.from({ length: 6 }).map((_, i) => (
                <tr key={i}>
                  {Array.from({ length: 7 }).map((_, j) => (
                    <td key={j}>
                      <div className={styles.skeletonCell} />
                    </td>
                  ))}
                </tr>
              ))}

            {!loading && scans.length === 0 && (
              <tr>
                <td colSpan={7}>
                  <EmptyState
                    icon="history"
                    title="No scans found"
                    message="Adjust your filters or submit a new URL in the Scanner"
                  />
                </td>
              </tr>
            )}

            {!loading &&
              scans.map((scan) => (
                <tr key={scan._id} className={styles.row}>
                  <td className={styles.urlCell} onClick={() => navigate(`/analysis/${scan._id}`)}>
                    <span className="material-symbols-rounded" style={{ fontSize: 14, color: 'var(--text-muted)' }}>
                      link
                    </span>
                    <span className={styles.urlText}>{scan.url}</span>
                  </td>
                  <td className={styles.mono}>{new Date(scan.submittedAt).toLocaleString()}</td>
                  <td>
                    {scan.threatScore !== undefined ? (
                      <span className={styles.scoreVal} style={{ color: scoreColor(scan.threatScore) }}>
                        {scan.threatScore}
                      </span>
                    ) : (
                      <span className={styles.dash}>-</span>
                    )}
                  </td>
                  <td>
                    <SeverityBadge level={scan.riskLevel} size="sm" />
                  </td>
                  <td>
                    <span className={`${styles.statusPill} ${styles[`status_${scan.status}`]}`}>
                      {scan.status === 'scanning' && <span className={styles.scanning} />}
                      {scan.status}
                    </span>
                  </td>
                  <td className={styles.mono}>{scan.iocs?.length ?? '-'}</td>
                  <td>
                    <div className={styles.actions}>
                      <button
                        className={styles.actionBtn}
                        onClick={() => navigate(`/analysis/${scan._id}`)}
                        title="View"
                      >
                        <span className="material-symbols-rounded">visibility</span>
                      </button>
                      <button
                        className={styles.actionBtn}
                        onClick={() => window.open(`/api/scans/${scan._id}/export`, '_blank')}
                        title="Export"
                      >
                        <span className="material-symbols-rounded">download</span>
                      </button>
                      <button
                        className={`${styles.actionBtn} ${styles.deleteBtn}`}
                        onClick={() => handleDelete(scan._id)}
                        title="Delete"
                      >
                        <span className="material-symbols-rounded">delete</span>
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>

      {totalPages > 1 && (
        <div className={styles.pagination}>
          <span className={styles.pageInfo}>
            Showing {((page - 1) * PAGE_SIZE) + 1}-{Math.min(page * PAGE_SIZE, total)} of {total}
          </span>
          <div className={styles.pageControls}>
            <button className={styles.pageBtn} disabled={page === 1} onClick={() => setPage(1)}>
              <span className="material-symbols-rounded">first_page</span>
            </button>
            <button className={styles.pageBtn} disabled={page === 1} onClick={() => setPage((p) => p - 1)}>
              <span className="material-symbols-rounded">chevron_left</span>
            </button>
            {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
              const p = Math.max(1, Math.min(page - 2, totalPages - 4)) + i;
              return (
                <button
                  key={p}
                  className={`${styles.pageBtn} ${p === page ? styles.activePage : ''}`}
                  onClick={() => setPage(p)}
                >
                  {p}
                </button>
              );
            })}
            <button
              className={styles.pageBtn}
              disabled={page === totalPages}
              onClick={() => setPage((p) => p + 1)}
            >
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

const scoreColor = (score) => {
  if (score < 26) return 'var(--safe-green)';
  if (score < 51) return 'var(--warn-amber)';
  if (score < 76) return '#f9784f';
  return 'var(--threat-red)';
};
