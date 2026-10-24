import { useState, useEffect, useCallback } from 'react';
import { Shield, Scan, AlertTriangle, CheckCircle, Activity, TrendingUp, Clock } from 'lucide-react';
import { fetchHealth, fetchHistory, fetchModelMetrics } from '../services/api';
import type { HealthResponse, HistoryResponse, ModelMetricsResponse } from '../types/api';

type Page = 'dashboard' | 'scanner' | 'history' | 'performance' | 'about';

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
        {sub && <div className="text-xs text-slate-600 mt-1">{sub}</div>}
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
        <div className="text-sm font-mono text-slate-200 truncate">{scan.submitted_url}</div>
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

  const load = useCallback(async () => {
    setLoading(true);
    const [h, hist, met] = await Promise.allSettled([
      fetchHealth(),
      fetchHistory(5),
      fetchModelMetrics(),
    ]);
    if (h.status === 'fulfilled') setHealth(h.value);
    if (hist.status === 'fulfilled') setHistoryData(hist.value);
    if (met.status === 'fulfilled') setMetrics(met.value);
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const stats = historyData?.stats;
  const tm = metrics?.test_metrics;

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
              Run <code className="font-mono bg-black/30 px-1 py-0.5 rounded">python -m backend.train_model</code> to train the detection model
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
        <button
          id="goto-scanner-btn"
          onClick={() => onNavigate('scanner')}
          className="btn-primary shrink-0"
        >
          <Scan size={18} />
          Open Scanner
        </button>
      </div>

      {/* Scan statistics */}
      <div>
        <h2 className="text-sm font-semibold text-slate-500 uppercase tracking-wider mb-4">Scan Statistics</h2>
        {loading ? (
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            {[0,1,2,3].map(i => (
              <div key={i} className="glass-card p-5 h-24 animate-pulse" style={{ background: 'rgba(10,21,53,0.6)' }} />
            ))}
          </div>
        ) : (
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard icon={<Activity size={20} />} label="Total Scans" value={stats?.total ?? 0} color="#3b82f6" />
            <StatCard icon={<AlertTriangle size={20} />} label="Phishing Found" value={stats?.phishing_count ?? 0} color="#ef4444" sub="High/Critical risk" />
            <StatCard icon={<CheckCircle size={20} />} label="Likely Legit" value={stats?.legitimate_count ?? 0} color="#10b981" sub="Low risk" />
            <StatCard icon={<TrendingUp size={20} />} label="Model Accuracy" value={tm ? `${(tm.test_accuracy * 100).toFixed(1)}%` : '—'} color="#8b5cf6" sub={tm ? 'Test set' : 'Train first'} />
          </div>
        )}
      </div>

      {/* Recent scans */}
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
          {loading ? (
            <div className="p-5 text-center text-slate-500 text-sm">Loading…</div>
          ) : historyData?.records?.length ? (
            <div>
              {historyData.records.map(r => <RecentScanRow key={r.id} scan={r} />)}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center p-10 text-center gap-3">
              <Shield size={32} className="text-slate-700" />
              <div className="text-slate-500 text-sm">No scans yet</div>
              <button onClick={() => onNavigate('scanner')} className="text-xs text-blue-400 hover:underline">
                Scan your first URL
              </button>
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
          {tm ? (
            <div className="p-5 space-y-3">
              {([
                ['Test Accuracy',      tm.test_accuracy,       '#3b82f6'],
                ['Phishing Recall',    tm.phishing_recall,     '#ef4444'],
                ['Phishing Precision', tm.phishing_precision,  '#f97316'],
                ['Macro F1-Score',     tm.macro_f1,            '#8b5cf6'],
              ] as [string, number, string][]).map(([label, val, color]) => (
                <div key={label}>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-slate-400">{label}</span>
                    <span className="font-mono font-semibold" style={{ color }}>{(val * 100).toFixed(1)}%</span>
                  </div>
                  <div className="h-1.5 rounded-full bg-slate-800">
                    <div className="h-full rounded-full transition-all duration-700"
                      style={{ width: `${val * 100}%`, background: color }} />
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center p-10 gap-3 text-center">
              <TrendingUp size={32} className="text-slate-700" />
              <div className="text-slate-500 text-sm">No metrics available</div>
              <div className="text-xs text-slate-600">Train the model to see evaluation results</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
