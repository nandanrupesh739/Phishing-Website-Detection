import { useState, useEffect } from 'react';
import { BarChart2, AlertTriangle, TrendingUp, Database, RefreshCw, Info } from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar,
  Cell
} from 'recharts';
import { fetchModelMetrics, fetchModelInfo } from '../services/api';
import type { ModelMetricsResponse, ModelInfoResponse } from '../types/api';

function MetricCard({ label, value, color = '#3b82f6', sub }: {
  label: string; value: number | null | undefined; color?: string; sub?: string;
}) {
  const isValid = typeof value === 'number' && !isNaN(value);
  const pct = isValid ? `${(value * 100).toFixed(1)}%` : '—';
  return (
    <div className="glass-card p-4 space-y-2">
      <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">{label}</div>
      <div className="text-3xl font-bold" style={{ color }}>{pct}</div>
      {sub && <div className="text-xs text-slate-500">{sub}</div>}
      {isValid && (
        <div className="h-1.5 rounded-full bg-slate-800">
          <div className="h-full rounded-full" style={{ width: `${Math.min(Math.max(value * 100, 0), 100)}%`, background: color }} />
        </div>
      )}
    </div>
  );
}

function ConfusionMatrix({ cm }: { cm?: number[][] | null }) {
  if (!cm || !Array.isArray(cm) || cm.length < 2 || !Array.isArray(cm[0])) {
    return <div className="text-slate-500 text-sm py-4">Confusion matrix unavailable</div>;
  }
  const labels = ['Phishing', 'Legitimate'];
  const total = cm.flat().reduce((a, b) => a + b, 0);

  return (
    <div className="space-y-2">
      <div className="text-xs text-slate-500 mb-3">
        Rows = Actual class · Columns = Predicted class
      </div>
      <div className="inline-grid gap-1" style={{ gridTemplateColumns: `auto repeat(${labels.length}, 1fr)` }}>
        <div />
        {labels.map(l => (
          <div key={l} className="text-center text-xs font-semibold text-slate-400 pb-1">↓ Pred {l}</div>
        ))}
        {cm.map((row, ri) => (
          <div key={`row-${ri}`} className="contents">
            <div key={`l${ri}`} className="text-xs font-semibold text-slate-400 pr-3 self-center">
              Actual {labels[ri]}
            </div>
            {row.map((val, ci) => {
              const pct = total ? ((val / total) * 100).toFixed(1) : '0';
              const isDiag = ri === ci;
              return (
                <div
                  key={`cell-${ri}-${ci}`}
                  className="flex flex-col items-center justify-center w-24 h-20 rounded-xl text-center"
                  style={{
                    background: isDiag ? 'rgba(16,185,129,0.12)' : 'rgba(239,68,68,0.08)',
                    border: `1px solid ${isDiag ? 'rgba(16,185,129,0.3)' : 'rgba(239,68,68,0.2)'}`,
                  }}
                >
                  <div className="text-xl font-bold" style={{ color: isDiag ? '#34d399' : '#f87171' }}>
                    {val.toLocaleString()}
                  </div>
                  <div className="text-xs text-slate-500">{pct}%</div>
                </div>
              );
            })}
          </div>
        ))}
      </div>
    </div>
  );
}

export default function ModelPerformance() {
  const [metrics, setMetrics] = useState<ModelMetricsResponse | null>(null);
  const [info, setInfo] = useState<ModelInfoResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const [m, i] = await Promise.all([fetchModelMetrics(), fetchModelInfo()]);
      setMetrics(m);
      setInfo(i);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load metrics');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center py-24 gap-4">
        <RefreshCw size={32} className="text-blue-400 animate-spin" />
        <div className="text-slate-400">Loading model metrics…</div>
      </div>
    );
  }

  if (error || !metrics) {
    return (
      <div className="max-w-2xl mx-auto">
        <div className="glass-card p-10 flex flex-col items-center gap-5 text-center">
          <div className="w-16 h-16 rounded-2xl flex items-center justify-center"
            style={{ background: 'rgba(245,158,11,0.1)', border: '1px solid rgba(245,158,11,0.3)' }}>
            <AlertTriangle size={32} className="text-amber-400" />
          </div>
          <div>
            <div className="text-white font-bold text-lg">No Model Metrics Available</div>
            <div className="text-slate-400 text-sm mt-2 max-w-sm">
              {error || 'Train the model first to see evaluation results.'}
            </div>
          </div>
          <div className="bg-black/30 rounded-lg px-4 py-3 text-xs font-mono text-blue-300 text-left">
            python train.py
          </div>
        </div>
      </div>
    );
  }

  const tm = metrics.test_metrics;
  const vc = metrics.validation_comparison;
  const fi = metrics.feature_importances?.slice(0, 12) ?? [];

  const testAcc = tm?.accuracy ?? tm?.test_accuracy ?? null;
  const phishF1 = tm?.f1 ?? tm?.phishing_f1 ?? null;
  const phishRec = tm?.recall ?? tm?.phishing_recall ?? null;
  const phishPrec = tm?.precision ?? tm?.phishing_precision ?? null;
  const legitF1 = tm?.legitimate_f1 ?? null;
  const macroF1 = tm?.macro_f1 ?? tm?.f1 ?? null;
  const rocAuc = tm?.roc_auc ?? null;
  const avgPrec = tm?.average_precision ?? null;

  // Comparison chart data
  const compData = (vc && typeof vc === 'object') ? Object.entries(vc).map(([name, vals]) => {
    const f1Val = vals?.phishing_f1 ?? vals?.f1 ?? 0;
    const recVal = vals?.phishing_recall ?? vals?.recall ?? 0;
    const accVal = vals?.accuracy ?? 0;
    return {
      name: name.replace(' ', '\n'),
      'Phishing F1': typeof f1Val === 'number' ? +(f1Val * 100).toFixed(1) : 0,
      'Phishing Recall': typeof recVal === 'number' ? +(recVal * 100).toFixed(1) : 0,
      'Accuracy': typeof accVal === 'number' ? +(accVal * 100).toFixed(1) : 0,
    };
  }) : [];

  // Radar data for selected model
  const radarData = [
    { metric: 'Accuracy',     value: typeof testAcc === 'number' ? +(testAcc * 100).toFixed(1) : 0 },
    { metric: 'Phish F1',     value: typeof phishF1 === 'number' ? +(phishF1 * 100).toFixed(1) : 0 },
    { metric: 'Phish Recall', value: typeof phishRec === 'number' ? +(phishRec * 100).toFixed(1) : 0 },
    { metric: 'Phish Prec.',  value: typeof phishPrec === 'number' ? +(phishPrec * 100).toFixed(1) : 0 },
    { metric: 'Legit F1',     value: typeof legitF1 === 'number' ? +(legitF1 * 100).toFixed(1) : 0 },
    { metric: 'ROC-AUC',      value: typeof rocAuc === 'number' ? +(rocAuc * 100).toFixed(1) : 0 },
  ];

  return (
    <div className="max-w-5xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <div className="p-2 rounded-lg" style={{ background: 'linear-gradient(135deg,rgba(139,92,246,0.2),rgba(59,130,246,0.2))' }}>
              <BarChart2 size={22} className="text-violet-400" />
            </div>
            Model Performance
          </h1>
          <p className="text-slate-400 text-sm mt-1 ml-11">
            {tm?.model_name ?? 'Production Model'} — Evaluated on held-out test set
          </p>
        </div>
        <button onClick={load} className="btn-ghost">
          <RefreshCw size={16} />
          Reload
        </button>
      </div>

      {/* Dataset info */}
      {info && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: 'Dataset',  value: 'PhiUSIIL', sub: 'UCI ML Repository' },
            { label: 'Records',  value: info.dataset_size?.toLocaleString() ?? '—', sub: 'After deduplication' },
            { label: 'Features', value: info.feature_count ?? '—', sub: 'URL-string features' },
            { label: 'Trained',  value: info.trained_at ? new Date(info.trained_at).toLocaleDateString() : '—', sub: `v${info.model_version ?? '—'}` },
          ].map(item => (
            <div key={item.label} className="glass-card p-4">
              <div className="text-xs text-slate-500 uppercase tracking-wider">{item.label}</div>
              <div className="text-lg font-bold text-white mt-1">{item.value}</div>
              <div className="text-xs text-slate-600 mt-0.5">{item.sub}</div>
            </div>
          ))}
        </div>
      )}

      {/* Key metrics grid */}
      <div>
        <h2 className="section-title"><TrendingUp size={18} className="text-violet-400" />Test Set Metrics</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <MetricCard label="Test Accuracy"      value={testAcc}   color="#3b82f6" sub="Overall correct predictions" />
          <MetricCard label="Phishing F1"        value={phishF1}   color="#ef4444" sub="Harmonic mean prec/recall" />
          <MetricCard label="Phishing Recall"    value={phishRec}  color="#f97316" sub="% phishing URLs caught" />
          <MetricCard label="Phishing Precision" value={phishPrec} color="#f59e0b" sub="% predictions correct" />
          <MetricCard label="Legitimate F1"      value={legitF1}   color="#10b981" sub="Legit URL performance" />
          <MetricCard label="Macro F1"           value={macroF1}   color="#8b5cf6" sub="Unweighted avg F1" />
          <MetricCard label="ROC-AUC"            value={rocAuc}    color="#06b6d4" sub="Area under ROC curve" />
          <MetricCard label="Avg Precision"      value={avgPrec}   color="#6366f1" sub="Precision-recall AUC" />
        </div>
      </div>

      {/* Charts row */}
      <div className="grid md:grid-cols-2 gap-6">
        {/* Confusion matrix */}
        <div className="glass-card p-6 space-y-4">
          <div className="section-title">
            <Database size={18} className="text-blue-400" />
            Confusion Matrix
          </div>
          <ConfusionMatrix cm={tm?.confusion_matrix} />
        </div>

        {/* Radar chart */}
        <div className="glass-card p-6 space-y-4">
          <div className="section-title">
            <BarChart2 size={18} className="text-violet-400" />
            Performance Radar
          </div>
          <ResponsiveContainer width="100%" height={220}>
            <RadarChart data={radarData}>
              <PolarGrid stroke="rgba(59,130,246,0.1)" />
              <PolarAngleAxis dataKey="metric" tick={{ fill: '#94a3b8', fontSize: 11 }} />
              <PolarRadiusAxis angle={30} domain={[0, 100]} tick={{ fill: '#475569', fontSize: 10 }} />
              <Radar name="Model" dataKey="value" stroke="#8b5cf6" fill="#8b5cf6" fillOpacity={0.15} strokeWidth={2} />
            </RadarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Model comparison */}
      {compData.length > 0 && (
        <div className="glass-card p-6 space-y-4">
          <div className="section-title">
            <BarChart2 size={18} className="text-blue-400" />
            Validation — Model Comparison
          </div>
          <p className="text-xs text-slate-500 -mt-2">
            All models trained on the same split. Best model selected by phishing class F1.
          </p>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={compData} margin={{ left: 0, right: 10, top: 5, bottom: 30 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(59,130,246,0.08)" />
              <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 12 }} />
              <YAxis domain={[0, 100]} tick={{ fill: '#94a3b8', fontSize: 11 }} unit="%" />
              <Tooltip
                contentStyle={{ background: 'rgba(10,21,53,0.95)', border: '1px solid rgba(59,130,246,0.3)', borderRadius: 8, color: '#f1f5f9' }}
                formatter={(v: number) => `${v}%`}
              />
              <Bar dataKey="Phishing F1"     fill="#ef4444" fillOpacity={0.8} radius={[4,4,0,0]} />
              <Bar dataKey="Phishing Recall" fill="#f97316" fillOpacity={0.8} radius={[4,4,0,0]} />
              <Bar dataKey="Accuracy"        fill="#3b82f6" fillOpacity={0.8} radius={[4,4,0,0]} />
            </BarChart>
          </ResponsiveContainer>
          <div className="flex gap-4 text-xs text-slate-500">
            {[['#ef4444','Phishing F1'],['#f97316','Phishing Recall'],['#3b82f6','Accuracy']].map(([c,l]) => (
              <div key={l} className="flex items-center gap-1.5">
                <div className="w-3 h-3 rounded-sm" style={{ background: c }} />
                {l}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Feature importances */}
      {fi.length > 0 && (
        <div className="glass-card p-6 space-y-4">
          <div className="section-title">
            <Info size={18} className="text-teal-400" />
            Top Feature Importances
          </div>
          <p className="text-xs text-slate-500 -mt-2">
            Higher values = more influence on model predictions. Derived from the selected model's internals.
          </p>
          <ResponsiveContainer width="100%" height={340}>
            <BarChart data={fi} layout="vertical" margin={{ left: 10, right: 20, top: 5, bottom: 5 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(59,130,246,0.08)" horizontal={false} />
              <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 11 }} />
              <YAxis type="category" dataKey="feature" width={160} tick={{ fill: '#94a3b8', fontSize: 11 }} />
              <Tooltip
                contentStyle={{ background: 'rgba(10,21,53,0.95)', border: '1px solid rgba(59,130,246,0.3)', borderRadius: 8, color: '#f1f5f9' }}
              />
              <Bar dataKey="importance" radius={[0,4,4,0]}>
                {fi.map((_, i) => (
                  <Cell key={i} fill={`hsl(${220 + i * 8}, 80%, ${55 - i * 1.5}%)`} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Recall trade-off note */}
      <div className="flex items-start gap-3 px-4 py-4 rounded-xl text-sm"
        style={{ background: 'rgba(59,130,246,0.05)', border: '1px solid rgba(59,130,246,0.15)' }}>
        <Info size={16} className="shrink-0 mt-0.5 text-blue-400" />
        <div className="text-slate-400 space-y-1">
          <div className="text-white font-medium">About Phishing Recall vs Precision</div>
          <p>
            In phishing detection, <strong className="text-white">recall</strong> (sensitivity) is prioritised over precision.
            A missed phishing URL (false negative) is more dangerous than a legitimate URL incorrectly flagged (false positive).
            Class weighting is applied during training to account for this asymmetry.
          </p>
          <p>
            New, targeted, or obfuscated phishing attacks may still evade the model.
            Do not rely on this tool as your sole security measure.
          </p>
        </div>
      </div>
    </div>
  );
}
