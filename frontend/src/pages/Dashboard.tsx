import { useState, useEffect, useCallback } from 'react';
import { Shield, Scan, AlertTriangle, CheckCircle, Activity, TrendingUp, Clock } from 'lucide-react';
import { fetchHealth, fetchHistory, fetchModelMetrics } from '../services/api';
import type { HealthResponse, HistoryResponse, ModelMetricsResponse } from '../types/api';
import { LoadingSkeleton } from '../components/LoadingSkeleton';
import { ErrorState } from '../components/ErrorState';
import { EmptyState } from '../components/EmptyState';
import { formatPercent, formatNumber } from '../utils/formatters';

type Page = 'dashboard' | 'scanner' | 'batch' | 'history' | 'performance' | 'about';

interface Props {
  onNavigate: (p: Page) => void;
}

function StatCard({
  icon, label, value, sub, color = '#3b82f6'
}: {
  icon: React.ReactNode; label: string; value: string | number; sub?: string; color?: string;
}) {
  return (
    <div className="glass-card-hover p-5 flex items-start gap-4">
      <div className="w-11 h-11 rounded-xl flex items-center justify-center shrink-0"
        style={{ background: `${color}18`, border: `1px solid ${color}30` }}>
        <div style={{ color }}>{icon}</div>
      </div>
      <div className="flex-1 min-w-0">
        <div className="text-2xl font-bold text-white">{value}</div>
        <div className="text-sm text-slate-400 mt-0.5">{label}</div>
        {sub && <div className="text-xs text-slate-500 mt-1">{sub}</div>}
      </div>
    </div>
  );
}

function RecentScanRow({ scan }: { scan: { submitted_url: string; prediction: string | null; risk_level: string | null; scan_timestamp: string } }) {
  const isPhishing = scan.prediction === 'PHISHING';
  const ts = new Date(scan.scan_timestamp).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });

  return (
    <div className="table-row flex items-center gap-4 px-4 py-3">
      <div className="shrink-0">
        {isPhishing
          ? <AlertTriangle size={16} className="text-red-400" />
          : <CheckCircle size={16} className="text-emerald-400" />
        }
      </div>
      <div className="flex-1 min-w-0">
        {/* Monospace plain text URL - NEVER a clickable link */}
        <div className="text-sm font-mono text-slate-200 truncate select-all">{scan.submitted_url}</div>
        <div className="text-xs text-slate-500 mt-0.5">{ts}</div>
      </div>
      <div className={`shrink-0 ${isPhishing ? 'badge-threat' : 'badge-safe'}`}>
        {scan.prediction ?? 'Error'}
      </div>
    </div>
  );
}

export default function Dashboard({ onNavigate }: Props) {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [historyData, setHistoryData] = useState<HistoryResponse | null>(null);
  const [metrics, setMetrics] = useState<ModelMetricsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [h, hist, met] = await Promise.allSettled([
        fetchHealth(),
        fetchHistory(5),
        fetchModelMetrics(),
      ]);

      if (h.status === 'fulfilled') setHealth(h.value);
      if (hist.status === 'fulfilled') setHistoryData(hist.value);
      if (met.status === 'fulfilled') setMetrics(met.value);

      if (h.status === 'rejected' && hist.status === 'rejected' && met.status === 'rejected') {
        const reason = h.reason instanceof Error ? h.reason.message : 'Backend server unreachable';
        setError(reason);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load dashboard data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const stats = historyData?.stats;
  const tm = metrics?.test_metrics;

  if (error && !health && !metrics) {
    return (
      <div className="max-w-3xl mx-auto py-8">
        <ErrorState
          title="Unable to connect to PhishGuard Backend"
          message={error}
          onRetry={load}
        />
      </div>
    );
  }

  return (
    <div className="space-y-8 max-w-5xl mx-auto">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-extrabold text-white flex items-center gap-3">
          <span className="shimmer-text">PhishGuard AI</span>
        </h1>
        <p className="text-slate-400 mt-1.5">
          Machine Learning–powered phishing URL detection • Educational project
        </p>
      </div>

      {/* Model status banner */}
      {health && !health.model_available && (
        <div className="flex items-center gap-4 p-4 rounded-xl"
          style={{ background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.3)' }}>
          <AlertTriangle size={20} className="text-amber-400 shrink-0" />
          <div className="flex-1">
            <div className="text-white font-semibold text-sm">Model not trained yet</div>
            <div className="text-amber-200/60 text-xs mt-0.5">
              Run <code className="font-mono bg-black/30 px-1 py-0.5 rounded">python train.py</code> to train the detection model
            </div>
          </div>
        </div>
      )}

      {/* Quick scan CTA */}
      <div className="glass-card p-6 flex flex-col md:flex-row items-start md:items-center gap-5"
        style={{ background: 'linear-gradient(135deg, rgba(59,130,246,0.08), rgba(139,92,246,0.08))', border: '1px solid rgba(59,130,246,0.2)' }}>
        <div className="flex-1">
          <div className="text-lg font-semibold text-white">Analyze a URL Now</div>
          <div className="text-slate-400 text-sm mt-1">Paste any URL to instantly check for phishing indicators</div>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          <button
            id="goto-scanner-btn"
            onClick={() => onNavigate('scanner')}
            className="btn-primary"
          >
            <Scan size={18} />
            Open Scanner
          </button>
          <button
            onClick={() => onNavigate('batch')}
            className="btn-ghost border border-slate-700/60"
          >
            Batch Scan
          </button>
        </div>
      </div>

      {/* Scan statistics */}
      <div>
        <h2 className="text-sm font-semibold text-slate-500 uppercase tracking-wider mb-4">Scan Statistics</h2>
        {loading && !stats && !tm ? (
          <LoadingSkeleton type="card" count={4} />
        ) : (
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard
              icon={<Activity size={20} />}
              label="Total Scans"
              value={formatNumber(stats?.total ?? 0)}
              color="#3b82f6"
            />
            <StatCard
              icon={<AlertTriangle size={20} />}
              label="Phishing Found"
              value={formatNumber(stats?.phishing_count ?? 0)}
              color="#ef4444"
              sub="High/Critical risk"
            />
            <StatCard
              icon={<CheckCircle size={20} />}
              label="Safe Found"
              value={formatNumber(stats?.legitimate_count ?? 0)}
              color="#10b981"
              sub="Low risk (Safe)"
            />
            <StatCard
              icon={<TrendingUp size={20} />}
              label="Model Accuracy"
              value={formatPercent(tm?.accuracy ?? tm?.test_accuracy)}
              color="#8b5cf6"
              sub={tm ? 'Test set, domain-grouped split' : 'Train first'}
            />
          </div>
        )}
      </div>

      {/* Recent scans & Model performance summary */}
      <div className="grid lg:grid-cols-2 gap-6">
        <div className="glass-card overflow-hidden">
          <div className="flex items-center justify-between px-5 py-4 border-b border-blue-900/20">
            <div className="flex items-center gap-2 text-sm font-semibold text-white">
              <Clock size={16} className="text-blue-400" />
              Recent Scans
            </div>
            <button
              onClick={() => onNavigate('history')}
              className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
            >
              View all →
            </button>
          </div>
          {loading && !historyData ? (
            <div className="p-5">
              <LoadingSkeleton type="lines" count={4} />
            </div>
          ) : historyData?.records?.length ? (
            <div>
              {historyData.records.map(r => <RecentScanRow key={r.id} scan={r} />)}
            </div>
          ) : (
            <div className="p-6">
              <EmptyState
                icon={<Shield size={28} className="text-slate-600" />}
                title="No scans yet"
                description="Scan history is clean. Analyze a URL to view real-time threat intelligence."
                action={{
                  label: 'Scan your first URL',
                  onClick: () => onNavigate('scanner')
                }}
              />
            </div>
          )}
        </div>

        {/* Model performance summary */}
        <div className="glass-card overflow-hidden">
          <div className="flex items-center justify-between px-5 py-4 border-b border-blue-900/20">
            <div className="flex items-center gap-2 text-sm font-semibold text-white">
              <TrendingUp size={16} className="text-violet-400" />
              Model Performance
            </div>
            <button
              onClick={() => onNavigate('performance')}
              className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
            >
              Full report →
            </button>
          </div>
          {loading && !tm ? (
            <div className="p-5">
              <LoadingSkeleton type="lines" count={4} />
            </div>
          ) : tm ? (
            <div className="p-5 space-y-3">
              {([
                ['Test Accuracy',      tm.accuracy ?? tm.test_accuracy,       '#3b82f6'],
                ['Phishing Recall',    tm.recall ?? tm.phishing_recall,     '#ef4444'],
                ['Phishing Precision', tm.precision ?? tm.phishing_precision,  '#f97316'],
                ['Macro F1-Score',     tm.macro_f1 ?? tm.f1 ?? tm.phishing_f1, '#8b5cf6'],
              ] as [string, number | undefined, string][]).map(([label, val, color]) => {
                const isValid = typeof val === 'number' && !isNaN(val);
                const pct = formatPercent(val);
                return (
                  <div key={label}>
                    <div className="flex justify-between text-xs mb-1">
                      <span className="text-slate-400">{label}</span>
                      <span className="font-mono font-semibold" style={{ color }}>{pct}</span>
                    </div>
                    <div className="h-1.5 rounded-full bg-slate-800">
                      {isValid && (
                        <div className="h-full rounded-full transition-all duration-700"
                          style={{ width: `${Math.min(Math.max((val ?? 0) * 100, 0), 100)}%`, background: color }} />
                      )}
                    </div>
                  </div>
                );
              })}
              <div className="text-[11px] text-slate-500 text-right pt-1">
                Split: Test set, domain-grouped split
              </div>
            </div>
          ) : (
            <div className="p-6">
              <EmptyState
                icon={<TrendingUp size={28} className="text-slate-600" />}
                title="No metrics available"
                description="Train the model to inspect evaluation scores, ROC curve, and confusion matrix."
              />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
