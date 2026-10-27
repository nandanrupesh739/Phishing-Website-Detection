import { useState, useEffect, useCallback } from 'react';
import { Shield, Scan, AlertTriangle, CheckCircle, Activity, TrendingUp, Clock } from 'lucide-react';
import { fetchHealth, fetchHistory, fetchModelMetrics, fetchExternalEval } from '../services/api';
import type { HealthResponse, HistoryResponse, ModelMetricsResponse, ExternalEvalResponse } from '../types/api';
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
  const [externalEval, setExternalEval] = useState<ExternalEvalResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [h, hist, met, ext] = await Promise.allSettled([
        fetchHealth(),
        fetchHistory(5),
        fetchModelMetrics(),
        fetchExternalEval(),
      ]);

      if (h.status === 'fulfilled') setHealth(h.value);
      if (hist.status === 'fulfilled') setHistoryData(hist.value);
      if (met.status === 'fulfilled') setMetrics(met.value);
      if (ext.status === 'fulfilled') setExternalEval(ext.value);

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

      {/* External Evaluation Card (Out-of-Distribution Benchmark) */}
      {externalEval?.available && externalEval.metrics && (
        <div className="glass-card p-6 space-y-4" style={{ border: '1px solid rgba(139,92,246,0.3)', background: 'linear-gradient(135deg, rgba(139,92,246,0.06), rgba(59,130,246,0.04))' }}>
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div>
              <div className="flex items-center gap-2 text-base font-bold text-white">
                <Shield size={18} className="text-violet-400" />
                External Benchmark Evaluation (Out-of-Distribution Test)
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Evaluated against real-world external feeds: <span className="font-mono text-slate-300">{externalEval.datasets?.phishing_file ?? 'phishing.txt'}</span> &amp; <span className="font-mono text-slate-300">{externalEval.datasets?.legit_file ?? 'legit.txt'}</span> ({formatNumber(externalEval.datasets?.total_samples)} total URLs)
              </p>
            </div>
            <span className="text-[11px] px-2.5 py-1 rounded-full bg-violet-500/20 text-violet-300 border border-violet-500/30 font-semibold">
              Independent Benchmark
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-1">
            <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-800">
              <div className="text-[11px] text-slate-400">Phishing Recall</div>
              <div className="text-xl font-bold text-amber-400 mt-0.5">
                {formatPercent(externalEval.metrics.phishing_recall)}
              </div>
              <div className="text-[10px] text-slate-500 mt-0.5">Caught external phish</div>
            </div>
            <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-800">
              <div className="text-[11px] text-slate-400">False Positive Rate</div>
              <div className="text-xl font-bold text-sky-400 mt-0.5">
                {formatPercent(externalEval.metrics.false_positive_rate)}
              </div>
              <div className="text-[10px] text-slate-500 mt-0.5">Legit false alarms</div>
            </div>
            <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-800">
              <div className="text-[11px] text-slate-400">Precision</div>
              <div className="text-xl font-bold text-emerald-400 mt-0.5">
                {formatPercent(externalEval.metrics.precision)}
              </div>
              <div className="text-[10px] text-slate-500 mt-0.5">True positive ratio</div>
            </div>
            <div className="bg-slate-900/60 p-3 rounded-lg border border-slate-800">
              <div className="text-[11px] text-slate-400">F1-Score</div>
              <div className="text-xl font-bold text-violet-400 mt-0.5">
                {formatPercent(externalEval.metrics.f1_score)}
              </div>
              <div className="text-[10px] text-slate-500 mt-0.5">Harmonic mean</div>
            </div>
          </div>
        </div>
      )}

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
