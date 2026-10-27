import { useState, useEffect, useCallback } from 'react';
import {
  History, AlertTriangle, CheckCircle, Trash2, Search, RefreshCw, AlertCircle,
  Activity, ArrowUpDown
} from 'lucide-react';
import { fetchHistory, clearHistory } from '../services/api';
import type { ScanRecord, HistoryStats } from '../types/api';
import { LoadingSkeleton } from '../components/LoadingSkeleton';
import { ErrorState } from '../components/ErrorState';
import { EmptyState } from '../components/EmptyState';
import { formatNumber } from '../utils/formatters';

const RISK_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH:     '#f97316',
  MEDIUM:   '#f59e0b',
  LOW:      '#10b981',
};

function RiskBadge({ level }: { level: string | null }) {
  const color = level ? RISK_COLORS[level] ?? '#94a3b8' : '#94a3b8';
  return (
    <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold"
      style={{ background: `${color}18`, color, border: `1px solid ${color}30` }}>
      {level ?? 'Unknown'}
    </span>
  );
}

function PredBadge({ pred }: { pred: string | null }) {
  if (!pred) return <span className="badge-neutral">Error</span>;
  if (pred === 'PHISHING') return (
    <div className="flex items-center gap-1.5 badge-threat">
      <AlertTriangle size={11} />
      Phishing
    </div>
  );
  return (
    <div className="flex items-center gap-1.5 badge-safe">
      <CheckCircle size={11} />
      Safe
    </div>
  );
}

function AdminClearDialog({
  isOpen,
  onClose,
  onConfirm,
  clearing,
  error,
  adminKey,
  setAdminKey,
}: {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
  clearing: boolean;
  error: string | null;
  adminKey: string;
  setAdminKey: (k: string) => void;
}) {
  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 animate-fade-in"
      role="dialog"
      aria-modal="true"
      aria-labelledby="clear-history-title"
    >
      <div className="glass-card p-6 max-w-md w-full space-y-4 animate-slide-up border border-red-500/30">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl flex items-center justify-center bg-red-500/10 border border-red-500/30 text-red-400">
            <Trash2 size={20} />
          </div>
          <div>
            <h3 id="clear-history-title" className="text-base font-bold text-white">Clear Scan History</h3>
            <p className="text-xs text-slate-400">This action cannot be undone</p>
          </div>
        </div>

        <p className="text-xs text-slate-300 leading-relaxed">
          All scan history records will be permanently deleted from the local database. If the backend is protected by an admin API key, provide it below.
        </p>

        <div>
          <label htmlFor="admin-key-input" className="block text-xs font-semibold text-slate-300 mb-1">
            Admin API Key (kept in memory only):
          </label>
          <input
            id="admin-key-input"
            type="password"
            value={adminKey}
            onChange={e => setAdminKey(e.target.value)}
            placeholder="Enter HISTORY_API_KEY (optional if not configured)"
            className="input-cyber w-full text-xs"
            autoComplete="off"
            spellCheck={false}
          />
          <div className="text-[11px] text-slate-500 mt-1">
            Leave blank if the server is running without a HISTORY_API_KEY.
          </div>
        </div>

        {error && (
          <div className="p-3 rounded-lg bg-red-950/40 border border-red-500/30 text-xs text-red-200 flex items-start gap-2" role="alert">
            <AlertTriangle size={15} className="text-red-400 shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        <div className="flex justify-end gap-2 pt-2">
          <button
            type="button"
            onClick={onClose}
            disabled={clearing}
            className="btn-ghost text-xs px-4 py-2"
          >
            Cancel
          </button>
          <button
            id="confirm-clear-btn"
            type="button"
            onClick={onConfirm}
            disabled={clearing}
            className="btn-danger text-xs px-4 py-2 flex items-center gap-1.5"
          >
            {clearing ? <RefreshCw size={13} className="animate-spin" /> : <Trash2 size={13} />}
            <span>{clearing ? 'Clearing…' : 'Clear All Records'}</span>
          </button>
        </div>
      </div>
    </div>
  );
}

export default function ScanHistory() {
  const [records, setRecords] = useState<ScanRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [stats, setStats] = useState<HistoryStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters, search, sorting
  const [search, setSearch] = useState('');
  const [predFilter, setPredFilter] = useState<'ALL' | 'SAFE' | 'PHISHING'>('ALL');
  const [riskFilter, setRiskFilter] = useState<string>('ALL');
  const [sortBy, setSortBy] = useState<'date_desc' | 'date_asc' | 'score_desc' | 'score_asc'>('date_desc');

  // Pagination (limit/offset from API)
  const [page, setPage] = useState(0);
  const PER_PAGE = 20;

  // Clear modal & admin key state (kept in memory only)
  const [showClearModal, setShowClearModal] = useState(false);
  const [adminKey, setAdminKey] = useState('');
  const [clearing, setClearing] = useState(false);
  const [clearError, setClearError] = useState<string | null>(null);

  const load = useCallback(async (pg = 0) => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchHistory(PER_PAGE, pg * PER_PAGE);
      setRecords(data.records);
      setTotal(data.total);
      if (data.stats) {
        setStats(data.stats);
      }
      setPage(pg);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to fetch scan history';
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(0); }, [load]);

  const handleClear = async () => {
    setClearing(true);
    setClearError(null);
    try {
      await clearHistory(adminKey.trim() || undefined);
      setShowClearModal(false);
      setAdminKey('');
      setRecords([]);
      setTotal(0);
      setStats({ total: 0, phishing_count: 0, legitimate_count: 0, error_count: 0 });
      load(0);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to clear history';
      setClearError(msg);
    } finally {
      setClearing(false);
    }
  };

  // Client-side filtering & sorting on current page records
  const filteredAndSorted = records
    .filter(r => {
      if (search) {
        const q = search.toLowerCase();
        const matchesUrl = r.submitted_url.toLowerCase().includes(q);
        const matchesPred = (r.prediction ?? '').toLowerCase().includes(q);
        const matchesRisk = (r.risk_level ?? '').toLowerCase().includes(q);
        if (!matchesUrl && !matchesPred && !matchesRisk) return false;
      }
      if (predFilter !== 'ALL') {
        if (predFilter === 'PHISHING' && r.prediction !== 'PHISHING') return false;
        if (predFilter === 'SAFE' && r.prediction !== 'SAFE' && r.prediction !== 'LIKELY LEGITIMATE') return false;
      }
      if (riskFilter !== 'ALL') {
        if (r.risk_level !== riskFilter) return false;
      }
      return true;
    })
    .sort((a, b) => {
      if (sortBy === 'date_desc') {
        return new Date(b.scan_timestamp).getTime() - new Date(a.scan_timestamp).getTime();
      }
      if (sortBy === 'date_asc') {
        return new Date(a.scan_timestamp).getTime() - new Date(b.scan_timestamp).getTime();
      }
      if (sortBy === 'score_desc') {
        return (b.model_score ?? 0) - (a.model_score ?? 0);
      }
      if (sortBy === 'score_asc') {
        return (a.model_score ?? 0) - (b.model_score ?? 0);
      }
      return 0;
    });

  // Respect Privacy Mode from Phase 4: check if stored records are domains/hashes
  const isPrivacyMode = records.some(r => r.submitted_url.includes('[sha256:') || r.submitted_url.includes('sha256:'));
  const totalPages = Math.ceil(total / PER_PAGE);

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      <AdminClearDialog
        isOpen={showClearModal}
        onClose={() => { setShowClearModal(false); setClearError(null); setAdminKey(''); }}
        onConfirm={handleClear}
        clearing={clearing}
        error={clearError}
        adminKey={adminKey}
        setAdminKey={setAdminKey}
      />

      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <div className="p-2 rounded-lg" style={{ background: 'linear-gradient(135deg,rgba(59,130,246,0.2),rgba(139,92,246,0.2))' }}>
              <History size={22} className="text-blue-400" />
            </div>
            Scan History
          </h1>
          <p className="text-slate-400 text-sm mt-1 ml-11">
            {formatNumber(total)} total record{total !== 1 ? 's' : ''} stored locally
            {isPrivacyMode && <span className="ml-2 text-cyan-400 font-mono text-xs">(Privacy Mode Active)</span>}
          </p>
        </div>
        <div className="flex gap-2">
          <button
            id="refresh-history-btn"
            onClick={() => load(page)}
            className="btn-ghost flex items-center gap-1.5"
            disabled={loading}
            aria-label="Refresh scan history"
          >
            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
            <span>Refresh</span>
          </button>
          {total > 0 && (
            <button
              id="clear-history-btn"
              onClick={() => { setShowClearModal(true); setClearError(null); }}
              disabled={clearing}
              className="btn-danger flex items-center gap-1.5"
              aria-label="Clear scan history"
            >
              <Trash2 size={16} />
              <span>Clear History</span>
            </button>
          )}
        </div>
      </div>

      {/* Real Stats Cards: Total, Safe, Phishing */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="glass-card p-4 flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-xl flex items-center justify-center bg-blue-500/10 border border-blue-500/30 text-blue-400">
            <Activity size={20} />
          </div>
          <div>
            <div className="text-xs text-slate-400 uppercase font-semibold">Total Scans</div>
            <div className="text-2xl font-bold text-white mt-0.5">{formatNumber(stats?.total ?? total)}</div>
          </div>
        </div>

        <div className="glass-card p-4 flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-xl flex items-center justify-center bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
            <CheckCircle size={20} />
          </div>
          <div>
            <div className="text-xs text-slate-400 uppercase font-semibold">Legitimate (Safe)</div>
            <div className="text-2xl font-bold text-emerald-400 mt-0.5">{formatNumber(stats?.legitimate_count ?? 0)}</div>
          </div>
        </div>

        <div className="glass-card p-4 flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-xl flex items-center justify-center bg-red-500/10 border border-red-500/30 text-red-400">
            <AlertTriangle size={20} />
          </div>
          <div>
            <div className="text-xs text-slate-400 uppercase font-semibold">Phishing Detections</div>
            <div className="text-2xl font-bold text-red-400 mt-0.5">{formatNumber(stats?.phishing_count ?? 0)}</div>
          </div>
        </div>
      </div>

      {/* Controls: Search, Prediction Filter, Risk Filter, Sort */}
      <div className="glass-card p-4 space-y-3">
        <div className="flex flex-col md:flex-row gap-3">
          {/* Search input */}
          <div className="relative flex-1">
            <label htmlFor="history-search" className="sr-only">Search scan history</label>
            <Search size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              id="history-search"
              type="text"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search by URL, prediction, or risk level…"
              className="input-cyber pl-9 w-full text-xs"
              aria-label="Search scan history"
            />
          </div>

          {/* Filters & Sorting */}
          <div className="flex flex-wrap items-center gap-2">
            {/* Prediction Filter */}
            <div className="flex items-center gap-1 bg-slate-900/80 p-1 rounded-lg border border-slate-800 text-xs" role="group" aria-label="Prediction Filter">
              <span className="text-[11px] text-slate-500 px-1 font-medium">Pred:</span>
              {(['ALL', 'SAFE', 'PHISHING'] as const).map(p => (
                <button
                  key={p}
                  type="button"
                  onClick={() => setPredFilter(p)}
                  aria-pressed={predFilter === p}
                  className={`px-2 py-1 rounded text-xs transition-colors ${
                    predFilter === p
                      ? 'bg-blue-600 text-white font-semibold'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  {p}
                </button>
              ))}
            </div>

            {/* Risk Level Filter */}
            <label htmlFor="risk-filter" className="sr-only">Filter by risk level</label>
            <select
              id="risk-filter"
              value={riskFilter}
              onChange={e => setRiskFilter(e.target.value)}
              className="bg-slate-900/80 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-blue-500"
              aria-label="Filter by Risk Level"
            >
              <option value="ALL">All Risk Levels</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>

            {/* Sort Selector */}
            <div className="flex items-center gap-1 bg-slate-900/80 border border-slate-800 rounded-lg px-2 py-1 text-xs text-slate-300">
              <ArrowUpDown size={13} className="text-slate-400" />
              <label htmlFor="sort-by" className="sr-only">Sort history by</label>
              <select
                id="sort-by"
                value={sortBy}
                onChange={e => setSortBy(e.target.value as any)}
                className="bg-transparent text-xs text-slate-300 focus:outline-none cursor-pointer"
                aria-label="Sort History By"
              >
                <option value="date_desc">Newest First</option>
                <option value="date_asc">Oldest First</option>
                <option value="score_desc">Highest Score</option>
                <option value="score_asc">Lowest Score</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      {/* Warning / Privacy Notice */}
      <div className="flex items-start gap-2.5 px-4 py-3 rounded-xl text-xs bg-slate-900/40 border border-slate-800 text-slate-400">
        <AlertCircle size={15} className="shrink-0 mt-0.5 text-blue-400" />
        <p>
          {isPrivacyMode ? (
            <>
              <strong className="text-slate-200">Privacy Mode active: </strong>
              Stored items show registered domains and cryptographic SHA-256 hashes only. Full raw URLs and query parameters are stripped before persistence.
            </>
          ) : (
            <>
              Scan records are persisted locally in SQLite on this host. Submitted URLs may contain sensitive tokens; clear records at any time.
            </>
          )}
        </p>
      </div>

      {/* Table / Results Container */}
      {error ? (
        <ErrorState
          title="Failed to Load History"
          message={error}
          onRetry={() => load(page)}
        />
      ) : loading ? (
        <LoadingSkeleton type="table" count={5} />
      ) : filteredAndSorted.length === 0 ? (
        <EmptyState
          icon={<History size={32} className="text-slate-600" />}
          title={search || predFilter !== 'ALL' || riskFilter !== 'ALL' ? 'No matching records found' : 'No scan history yet'}
          description={
            search || predFilter !== 'ALL' || riskFilter !== 'ALL'
              ? 'Try adjusting your search criteria or resetting the prediction and risk level filters.'
              : 'Scan a URL on the Scanner page to record threat intelligence logs.'
          }
        />
      ) : (
        <div className="glass-card overflow-hidden">
          {/* Responsive Table Scroll Container */}
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs" style={{ minWidth: 640 }}>
              <thead>
                <tr className="border-b border-blue-900/20 text-slate-400 uppercase tracking-wider bg-slate-900/50">
                  <th className="px-4 py-3 font-semibold">
                    {/* Respect privacy mode: do not label column URL if domain/hash */}
                    {isPrivacyMode ? 'Domain / SHA-256 Hash' : 'Submitted URL'}
                  </th>
                  <th className="px-4 py-3 text-center font-semibold w-28">Prediction</th>
                  <th className="px-4 py-3 text-center font-semibold w-24">Risk</th>
                  <th className="px-4 py-3 text-right font-semibold w-24">Score</th>
                  <th className="px-4 py-3 text-right font-semibold w-32">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredAndSorted.map(r => {
                  const ts = new Date(r.scan_timestamp);
                  const dateStr = ts.toLocaleString(undefined, {
                    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
                  });
                  const isRowAnonymized = r.submitted_url.includes('[sha256:') || r.submitted_url.includes('sha256:');

                  return (
                    <tr key={r.id} className="hover:bg-blue-900/10 transition-colors">
                      <td className="px-4 py-3 max-w-xs md:max-w-md">
                        {/* Monospace, plain text, never clickable */}
                        <div className="font-mono text-xs text-slate-200 truncate select-all" title={r.submitted_url}>
                          {r.submitted_url}
                        </div>
                        <div className="flex items-center gap-2 mt-0.5">
                          {r.model_version && (
                            <span className="text-[10px] text-slate-500 font-mono">v{r.model_version}</span>
                          )}
                          {isRowAnonymized && (
                            <span className="px-1.5 py-0.2 rounded text-[9px] bg-cyan-950/80 text-cyan-400 border border-cyan-800/40 font-mono">
                              Anonymized
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-center">
                        <PredBadge pred={r.prediction} />
                      </td>
                      <td className="px-4 py-3 text-center">
                        <RiskBadge level={r.risk_level} />
                      </td>
                      <td className="px-4 py-3 text-right font-mono text-slate-300">
                        {r.model_score !== null && r.model_score !== undefined
                          ? `${(r.model_score * 100).toFixed(1)}%`
                          : '—'}
                      </td>
                      <td className="px-4 py-3 text-right text-slate-400 whitespace-nowrap">
                        {dateStr}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Pagination Controls */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between px-4 py-3 border-t border-slate-800/80 text-xs">
              <span className="text-slate-400">
                Page {page + 1} of {totalPages} ({formatNumber(total)} total scans)
              </span>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => load(page - 1)}
                  disabled={page === 0 || loading}
                  className="btn-ghost px-3 py-1 text-xs border border-slate-700/60"
                  aria-label="Previous Page"
                >
                  ← Previous
                </button>
                <button
                  type="button"
                  onClick={() => load(page + 1)}
                  disabled={page >= totalPages - 1 || loading}
                  className="btn-ghost px-3 py-1 text-xs border border-slate-700/60"
                  aria-label="Next Page"
                >
                  Next →
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
