import { useState, useEffect, useCallback } from 'react';
import { History, AlertTriangle, CheckCircle, Trash2, Search, RefreshCw, AlertCircle } from 'lucide-react';
import { fetchHistory, clearHistory } from '../services/api';
import type { ScanRecord } from '../types/api';

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

function ConfirmDialog({ onConfirm, onCancel }: { onConfirm: () => void; onCancel: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm animate-fade-in">
      <div className="glass-card p-6 max-w-sm w-full mx-4 space-y-4 animate-slide-up">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl flex items-center justify-center"
            style={{ background: 'rgba(239,68,68,0.12)', border: '1px solid rgba(239,68,68,0.3)' }}>
            <Trash2 size={18} className="text-red-400" />
          </div>
          <div>
            <div className="font-semibold text-white">Clear Scan History</div>
            <div className="text-sm text-slate-400">This cannot be undone</div>
          </div>
        </div>
        <p className="text-sm text-slate-400">
          All scan records will be permanently deleted from the local database.
          This action is irreversible.
        </p>
        <div className="flex gap-3 pt-1">
          <button onClick={onCancel} className="btn-ghost flex-1 justify-center">Cancel</button>
          <button id="confirm-clear-btn" onClick={onConfirm} className="btn-danger flex-1 justify-center">
            <Trash2 size={14} />
            Clear All
          </button>
        </div>
      </div>
    </div>
  );
}

export default function ScanHistory() {
  const [records, setRecords] = useState<ScanRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [clearing, setClearing] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(0);
  const PER_PAGE = 20;

  const load = useCallback(async (pg = 0) => {
    setLoading(true);
    try {
      const data = await fetchHistory(PER_PAGE, pg * PER_PAGE);
      setRecords(data.records);
      setTotal(data.total);
      setPage(pg);
    } catch {
      // connection error handled by empty state
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleClear = async () => {
    setShowConfirm(false);
    setClearing(true);
    try {
      await clearHistory();
      setRecords([]);
      setTotal(0);
    } catch { /* ignore */ }
    setClearing(false);
  };

  const filtered = records.filter(r =>
    !search ||
    r.submitted_url.toLowerCase().includes(search.toLowerCase()) ||
    (r.prediction ?? '').toLowerCase().includes(search.toLowerCase())
  );

  const totalPages = Math.ceil(total / PER_PAGE);

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      {showConfirm && (
        <ConfirmDialog
          onConfirm={handleClear}
          onCancel={() => setShowConfirm(false)}
        />
      )}

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
            {total} total record{total !== 1 ? 's' : ''} stored locally
          </p>
        </div>
        <div className="flex gap-2">
          <button id="refresh-history-btn" onClick={() => load()} className="btn-ghost" disabled={loading}>
            <RefreshCw size={16} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
          {total > 0 && (
            <button
              id="clear-history-btn"
              onClick={() => setShowConfirm(true)}
              disabled={clearing}
              className="btn-danger"
            >
              <Trash2 size={16} />
              {clearing ? 'Clearing…' : 'Clear All'}
            </button>
          )}
        </div>
      </div>

      {/* Search */}
      <div className="relative">
        <Search size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" />
        <input
          id="history-search"
          type="text"
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Filter by URL or prediction…"
          className="input-cyber pl-9"
        />
      </div>

      {/* Warning about URL sensitivity */}
      <div className="flex items-start gap-2.5 px-4 py-3 rounded-xl text-xs"
        style={{ background: 'rgba(100,116,139,0.08)', border: '1px solid rgba(100,116,139,0.15)', color: '#94a3b8' }}>
        <AlertCircle size={14} className="shrink-0 mt-0.5 text-slate-500" />
        <p>
          Scan history is stored locally on this machine only. URLs may contain sensitive query parameters —
          use "Clear All" to remove records you no longer need.
        </p>
      </div>

      {/* Table */}
      <div className="glass-card overflow-hidden">
        {loading ? (
          <div className="p-12 flex flex-col items-center gap-4">
            <RefreshCw size={28} className="text-slate-600 animate-spin" />
            <div className="text-slate-500 text-sm">Loading history…</div>
          </div>
        ) : filtered.length === 0 ? (
          <div className="p-12 flex flex-col items-center gap-4 text-center">
            <History size={36} className="text-slate-700" />
            <div>
              <div className="text-slate-400 font-medium">
                {search ? 'No records match your filter' : 'No scan history yet'}
              </div>
              <div className="text-slate-600 text-sm mt-1">
                {search ? 'Try a different search term' : 'Scan a URL to see results here'}
              </div>
            </div>
          </div>
        ) : (
          <>
            {/* Table header */}
            <div className="grid grid-cols-12 gap-4 px-4 py-2.5 border-b border-blue-900/20 text-xs font-semibold uppercase tracking-wider text-slate-500">
              <div className="col-span-5">URL</div>
              <div className="col-span-2 text-center">Prediction</div>
              <div className="col-span-2 text-center">Risk</div>
              <div className="col-span-2 text-right">Score</div>
              <div className="col-span-1 text-right">Time</div>
            </div>
            {/* Table rows */}
            <div>
              {filtered.map(r => {
                const ts = new Date(r.scan_timestamp);
                const dateStr = ts.toLocaleString(undefined, {
                  month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
                });
                return (
                  <div key={r.id} className="table-row grid grid-cols-12 gap-4 px-4 py-3 items-center">
                    <div className="col-span-5 min-w-0">
                      <div className="font-mono text-sm text-slate-200 truncate" title={r.submitted_url}>
                        {r.submitted_url}
                      </div>
                      {r.model_version && (
                        <div className="text-xs text-slate-600 mt-0.5">v{r.model_version}</div>
                      )}
                    </div>
                    <div className="col-span-2 flex justify-center">
                      <PredBadge pred={r.prediction} />
                    </div>
                    <div className="col-span-2 flex justify-center">
                      <RiskBadge level={r.risk_level} />
                    </div>
                    <div className="col-span-2 text-right">
                      {r.model_score !== null && r.model_score !== undefined ? (
                        <span className="font-mono text-sm text-slate-300">
                          {(r.model_score * 100).toFixed(1)}%
                        </span>
                      ) : (
                        <span className="text-slate-600 text-sm">—</span>
                      )}
                    </div>
                    <div className="col-span-1 text-right text-xs text-slate-500 whitespace-nowrap">
                      {dateStr}
                    </div>
                  </div>
                );
              })}
            </div>
          </>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between text-sm">
          <span className="text-slate-500">
            Page {page + 1} of {totalPages}
          </span>
          <div className="flex gap-2">
            <button
              onClick={() => load(page - 1)}
              disabled={page === 0 || loading}
              className="btn-ghost px-3 py-1.5 text-xs"
            >
              ← Previous
            </button>
            <button
              onClick={() => load(page + 1)}
              disabled={page >= totalPages - 1 || loading}
              className="btn-ghost px-3 py-1.5 text-xs"
            >
              Next →
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
