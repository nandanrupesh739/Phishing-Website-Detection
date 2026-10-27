import { useState, useRef } from 'react';
import {
  Scan, AlertTriangle, CheckCircle, XCircle, Copy, Check,
  Shield, Info, ChevronDown, ChevronUp, Loader2, Link2,
  FileSpreadsheet, Upload, Download, RefreshCw, HelpCircle,
  EyeOff
} from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell
} from 'recharts';
import { predictUrl, predictBatch } from '../services/api';
import type { PredictionResult, BatchPredictionResponse } from '../types/api';

const RISK_CONFIG = {
  CRITICAL: { label: 'Critical Risk', color: '#ef4444', bg: 'rgba(239,68,68,0.1)', border: 'rgba(239,68,68,0.4)', icon: XCircle },
  HIGH:     { label: 'High Risk',     color: '#f97316', bg: 'rgba(249,115,22,0.1)', border: 'rgba(249,115,22,0.4)', icon: AlertTriangle },
  MEDIUM:   { label: 'Medium Risk',   color: '#f59e0b', bg: 'rgba(245,158,11,0.1)', border: 'rgba(245,158,11,0.4)', icon: AlertTriangle },
  LOW:      { label: 'Low Risk',      color: '#10b981', bg: 'rgba(16,185,129,0.1)', border: 'rgba(16,185,129,0.4)', icon: CheckCircle },
};

function ScoreBar({
  confidence,
  prediction,
  threshold
}: {
  confidence: number | null;
  prediction: string | null;
  threshold?: number;
}) {
  if (confidence === null) return null;
  const isPhishing = prediction === 'PHISHING';
  const color = isPhishing
    ? (confidence >= 85 ? '#ef4444' : confidence >= 65 ? '#f97316' : '#f59e0b')
    : '#10b981';

  return (
    <div className="space-y-2">
      <div className="flex justify-between items-center text-xs">
        <span className="text-slate-400">Model Confidence</span>
        <div className="flex items-center gap-2">
          {threshold !== undefined && (
            <span className="text-slate-500 font-mono text-[11px] px-2 py-0.5 rounded bg-slate-800/80 border border-slate-700/60">
              Threshold: {threshold.toFixed(4)}
            </span>
          )}
          <span className="font-mono font-bold text-sm" style={{ color }}>
            {confidence.toFixed(1)}%
          </span>
        </div>
      </div>
      <div className="h-2.5 rounded-full bg-slate-800 overflow-hidden relative">
        <div
          className="h-full rounded-full transition-all duration-700 ease-out"
          style={{ width: `${Math.min(100, Math.max(0, confidence))}%`, background: color, boxShadow: `0 0 10px ${color}80` }}
        />
      </div>
      <div className="flex justify-between text-[11px] text-slate-500">
        <span>0% (Uncertain)</span>
        <span>Calibrated Decision Level</span>
        <span>100% (High Confidence)</span>
      </div>
    </div>
  );
}

export function ExplanationSection({ result }: { result: PredictionResult }) {
  const [open, setOpen] = useState(true);

  // Top 5 contributing features from backend explanation field (or fallback to feature_contributions)
  const contributions = (result.explanation && result.explanation.length > 0)
    ? result.explanation.slice(0, 5)
    : (result.feature_contributions ? result.feature_contributions.slice(0, 5) : []);

  const chartData = contributions.map(c => ({
    feature: c.feature.length > 22 ? c.feature.slice(0, 20) + '…' : c.feature,
    rawFeature: c.feature,
    contribution: c.contribution,
    direction: c.direction,
  }));

  const indicators = result.indicators || [];

  return (
    <div className="glass-card overflow-hidden" data-testid="why-this-result-panel">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-5 py-4 text-sm font-semibold text-white hover:text-blue-300 transition-colors"
        aria-expanded={open}
      >
        <div className="flex items-center gap-2">
          <HelpCircle size={17} className="text-teal-400" />
          <span>Why this result? (Model Attribution & Indicators)</span>
        </div>
        {open ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
      </button>

      {open && (
        <div className="px-5 pb-5 border-t border-slate-800 space-y-4 pt-4">
          {/* Transparency Disclaimer Banner */}
          <div className="p-3 rounded-lg bg-blue-950/30 border border-blue-500/25 text-xs text-slate-300 flex items-start gap-2.5">
            <Info size={15} className="text-blue-400 shrink-0 mt-0.5" />
            <div>
              <span className="font-semibold text-white">Model Behaviour Explanation: </span>
              This panel visualizes the internal features that contributed most heavily to the model's prediction score.
              This represents an explanation of the machine learning model's behaviour, not legal or definitive forensic proof.
            </div>
          </div>

          {/* Top 5 Feature Contributions Recharts Horizontal Bar Chart */}
          {chartData.length > 0 ? (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs font-semibold text-slate-200">
                <span>Top Contributing Features:</span>
                <span className="text-[11px] text-slate-400 font-normal">
                  (Positive = pushes toward PHISHING, Negative = pushes toward SAFE)
                </span>
              </div>

              <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80">
                <ResponsiveContainer width="100%" height={Math.max(160, chartData.length * 36)}>
                  <BarChart
                    layout="vertical"
                    data={chartData}
                    margin={{ left: 10, right: 30, top: 8, bottom: 8 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="rgba(59,130,246,0.1)" />
                    <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 11 }} />
                    <YAxis type="category" dataKey="feature" width={140} tick={{ fill: '#94a3b8', fontSize: 11 }} />
                    <Tooltip
                      contentStyle={{
                        background: 'rgba(10,21,53,0.95)',
                        border: '1px solid rgba(59,130,246,0.3)',
                        borderRadius: 8,
                        color: '#f1f5f9',
                        fontSize: 12,
                      }}
                      formatter={(val: number, _name: string, props: any) => {
                        const dir = props?.payload?.direction;
                        const sign = val > 0 ? `+${val.toFixed(4)}` : val.toFixed(4);
                        return [`${sign} (${dir === 'PHISHING' ? 'Toward Phishing' : 'Toward Safe'})`, 'Contribution'];
                      }}
                    />
                    <Bar dataKey="contribution" radius={[0, 4, 4, 0]}>
                      {chartData.map((entry, index) => (
                        <Cell
                          key={`cell-${index}`}
                          fill={entry.direction === 'PHISHING' ? '#ef4444' : '#10b981'}
                        />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>

                <div className="flex items-center justify-between text-[11px] text-slate-400 pt-2 border-t border-slate-900 mt-2 px-1">
                  <div className="flex items-center gap-3">
                    <span className="flex items-center gap-1.5 text-red-300">
                      <span className="w-2.5 h-2.5 rounded-sm bg-red-500" /> Toward PHISHING
                    </span>
                    <span className="flex items-center gap-1.5 text-emerald-300">
                      <span className="w-2.5 h-2.5 rounded-sm bg-emerald-500" /> Toward SAFE
                    </span>
                  </div>
                  <span className="font-mono text-slate-500">TreeSHAP Local Attribution</span>
                </div>
              </div>
            </div>
          ) : (
            <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 text-xs text-slate-400 text-center">
              No feature attribution data available for this prediction.
            </div>
          )}

          {/* Observed Human-Readable Indicators */}
          {indicators.length > 0 && (
            <div className="space-y-2 pt-1">
              <div className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                <AlertTriangle size={14} className="text-amber-400" />
                <span>Observed Heuristic Indicators ({indicators.length})</span>
              </div>
              <ul className="space-y-1.5">
                {indicators.map((ind, i) => (
                  <li key={i} className="flex items-start gap-2 p-2 rounded-lg bg-slate-900/40 border border-slate-800/60 text-xs text-amber-200">
                    <span className="w-1.5 h-1.5 rounded-full mt-1.5 shrink-0 bg-amber-400" />
                    <span>{ind}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function FeatureTable({ features }: { features: Record<string, number> }) {
  const [expanded, setExpanded] = useState(false);
  const entries = Object.entries(features);
  const visible = expanded ? entries : entries.slice(0, 10);

  return (
    <div className="space-y-2">
      <div className="grid grid-cols-2 gap-1.5">
        {visible.map(([key, val]) => (
          <div key={key} className="flex justify-between items-center px-2.5 py-1.5 rounded-lg bg-slate-900/60 border border-slate-800/80 text-xs">
            <span className="text-slate-400 font-mono truncate pr-2" title={key}>{key.replace(/_/g, ' ')}</span>
            <span className={`font-mono font-semibold shrink-0 ${val > 0 ? 'text-cyan-400' : 'text-slate-500'}`}>
              {typeof val === 'number' ? (val % 1 === 0 ? val.toFixed(0) : val.toFixed(3)) : val}
            </span>
          </div>
        ))}
      </div>
      {entries.length > 10 && (
        <button
          onClick={() => setExpanded(e => !e)}
          className="w-full flex items-center justify-center gap-1.5 py-1.5 text-xs text-blue-400 hover:text-blue-300 transition-colors"
        >
          {expanded ? <><ChevronUp size={14} /> Show less</> : <><ChevronDown size={14} /> Show all {entries.length} features</>}
        </button>
      )}
    </div>
  );
}

export interface ScannerProps {
  initialTab?: 'single' | 'batch';
  onSwitchTab?: (tab: 'single' | 'batch') => void;
}

export default function Scanner({ initialTab = 'single', onSwitchTab }: ScannerProps = {}) {
  const [url, setUrl] = useState('');
  const [anonymize, setAnonymize] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<PredictionResult | null>(null);
  const [error, setError] = useState('');
  const [isOffline, setIsOffline] = useState(false);
  const [copiedResult, setCopiedResult] = useState(false);
  const [copiedUrl, setCopiedUrl] = useState(false);
  const [showFeatures, setShowFeatures] = useState(false);

  // Batch scanner state
  const [showBatch, setShowBatch] = useState(initialTab === 'batch');
  const [batchInput, setBatchInput] = useState('');
  const [batchLoading, setBatchLoading] = useState(false);
  const [batchResult, setBatchResult] = useState<BatchPredictionResponse | null>(null);
  const [batchError, setBatchError] = useState('');

  const inputRef = useRef<HTMLInputElement>(null);

  const validateBrowserUrl = (inputVal: string): string | null => {
    const trimmed = inputVal.trim();
    if (!trimmed) {
      return 'Please enter a URL to scan.';
    }
    if (trimmed.length > 2048) {
      return `URL exceeds 2048 characters maximum limit (current length: ${trimmed.length} chars).`;
    }
    // Reject non-http/https schemes if a scheme is present
    if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(trimmed)) {
      const scheme = trimmed.split(':')[0].toLowerCase();
      if (scheme !== 'http' && scheme !== 'https') {
        return `Unsupported scheme "${scheme}:". Only http:// and https:// URLs are permitted.`;
      }
    }
    return null;
  };

  const handleScan = async () => {
    const trimmed = url.trim();
    const valError = validateBrowserUrl(trimmed);
    if (valError) {
      setError(valError);
      return;
    }

    setError('');
    setIsOffline(false);
    setLoading(true);
    setResult(null);

    try {
      const res = await predictUrl(trimmed, anonymize);
      if (res.error) {
        setError(res.error);
      } else {
        setResult(res);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Unknown error';
      if (msg.includes('Failed to fetch') || msg.includes('NetworkError') || msg.includes('HTTP 503') || msg.includes('offline')) {
        setIsOffline(true);
        setError('Backend service is offline or unreachable. Start it with python -m backend.app');
      } else {
        setError(msg);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleBatchScan = async () => {
    const urls = batchInput
      .split('\n')
      .map(u => u.trim())
      .filter(u => u.length > 0 && !u.startsWith('#'));

    if (urls.length === 0) {
      setBatchError('Please provide at least one URL to scan.');
      return;
    }
    if (urls.length > 100) {
      setBatchError(`Maximum 100 URLs per batch allowed. You entered ${urls.length} URLs.`);
      return;
    }

    setBatchError('');
    setBatchLoading(true);
    setBatchResult(null);

    try {
      const res = await predictBatch(urls, anonymize);
      setBatchResult(res);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Batch scan failed';
      setBatchError(msg);
    } finally {
      setBatchLoading(false);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = ev => {
      const text = ev.target?.result as string;
      if (text) {
        // Extract URLs from CSV column or newline-separated lines
        const lines = text
          .split(/\r?\n/)
          .map(l => l.split(',')[0].replace(/^["']|["']$/g, '').trim())
          .filter(l => l && !l.toLowerCase().startsWith('url'));
        setBatchInput(lines.slice(0, 100).join('\n'));
      }
    };
    reader.readAsText(file);
  };

  const handleDownloadCsv = () => {
    if (!batchResult || batchResult.results.length === 0) return;

    const headers = ['URL', 'Prediction', 'Confidence', 'Risk Level', 'Score', 'Indicators'];
    const rows = batchResult.results.map(r => [
      `"${r.url.replace(/"/g, '""')}"`,
      r.prediction ?? 'ERROR',
      r.confidence !== null && r.confidence !== undefined ? `${r.confidence}%` : 'N/A',
      r.risk_level ?? 'UNKNOWN',
      r.score ?? '',
      `"${(r.indicators || []).join('; ').replace(/"/g, '""')}"`,
    ]);

    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `phishguard_batch_results_${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
  };

  const handleCopyUrl = () => {
    if (!result) return;
    navigator.clipboard.writeText(result.url).then(() => {
      setCopiedUrl(true);
      setTimeout(() => setCopiedUrl(false), 2000);
    });
  };

  const handleCopyResult = () => {
    if (!result) return;
    const phishProbStr = result.phishing_probability !== undefined && result.phishing_probability !== null
      ? `${(result.phishing_probability * 100).toFixed(1)}%`
      : (result.score !== null && result.score !== undefined ? `${(result.score * 100).toFixed(1)}%` : 'N/A');

    const lines = [
      '=== PhishGuard AI URL Scan Result ===',
      `URL: ${result.url}`,
      `Prediction: ${result.prediction ?? 'UNKNOWN'}`,
      `Calibrated Confidence: ${result.confidence !== null && result.confidence !== undefined ? `${result.confidence.toFixed(1)}%` : 'N/A'}`,
      `Phishing Probability: ${phishProbStr}`,
      `Risk Level: ${result.risk_level ?? 'UNKNOWN'}`,
      `Decision Threshold: ${result.threshold !== undefined && result.threshold !== null ? result.threshold.toFixed(4) : '0.5000'}`,
      `Model Version: ${result.model_version ?? 'v2.0.0'}`,
      `Risk Indicators: ${result.indicators && result.indicators.length > 0 ? result.indicators.join('; ') : 'None detected'}`,
      'Disclaimer: URL-only estimate based on lexical/structural patterns, not a guarantee. The system does not visit the website.',
    ];
    navigator.clipboard.writeText(lines.join('\n')).then(() => {
      setCopiedResult(true);
      setTimeout(() => setCopiedResult(false), 2000);
    });
  };

  const riskCfg = result?.risk_level ? RISK_CONFIG[result.risk_level as keyof typeof RISK_CONFIG] : null;
  const RiskIcon = riskCfg?.icon ?? Shield;

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <div className="p-2 rounded-lg" style={{ background: 'linear-gradient(135deg,rgba(59,130,246,0.25),rgba(139,92,246,0.25))' }}>
              <Scan size={22} className="text-blue-400" />
            </div>
            PhishGuard Scanner
          </h1>
          <p className="text-slate-400 text-sm mt-1 ml-11">
            Real-time URL classification with calibrated confidence estimates
          </p>
        </div>
        <button
          onClick={() => {
            const next = !showBatch;
            setShowBatch(next);
            onSwitchTab?.(next ? 'batch' : 'single');
          }}
          className="btn-ghost self-start sm:self-auto text-xs flex items-center gap-1.5 border border-slate-700/60"
        >
          <FileSpreadsheet size={15} className="text-teal-400" />
          <span>{showBatch ? 'Single Scanner' : 'Batch CSV Scanner'}</span>
        </button>
      </div>

      {/* Offline Error Alert */}
      {isOffline && (
        <div className="p-4 rounded-xl flex items-start gap-3 bg-red-950/30 border border-red-500/30 text-red-200">
          <AlertTriangle size={20} className="text-red-400 shrink-0 mt-0.5" />
          <div className="space-y-1 text-sm flex-1">
            <div className="font-semibold text-white">Backend Offline / Model Unavailable</div>
            <p className="text-slate-300">
              The Flask backend server (port 5000) could not be contacted or the model bundle is uninitialised.
            </p>
            <div className="font-mono text-xs bg-slate-900/60 p-2 rounded text-slate-300 mt-2">
              Run: python train.py &amp;&amp; python -m backend.app
            </div>
            <button
              onClick={handleScan}
              className="mt-2 text-xs font-semibold text-blue-400 hover:text-blue-300 flex items-center gap-1"
            >
              <RefreshCw size={12} /> Retry connection
            </button>
          </div>
        </div>
      )}

      {/* Main Single Scanner Input Card */}
      {!showBatch && (
        <div className="glass-card p-6 space-y-4">
          <div className="flex items-center justify-between text-sm text-slate-400 mb-1">
            <div className="flex items-center gap-2">
              <Link2 size={14} className="text-blue-400" />
              <span>Enter target URL:</span>
            </div>
            <span className={`text-xs font-mono ${url.length > 2000 ? 'text-red-400' : 'text-slate-500'}`}>
              {url.length} / 2048 chars
            </span>
          </div>

          <div className="flex gap-3">
            <div className="flex-1 relative">
              <input
                id="url-input"
                ref={inputRef}
                type="text"
                value={url}
                onChange={e => setUrl(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleScan()}
                placeholder="https://paypal.com.evil.xyz/login"
                className="input-cyber w-full pr-10"
                disabled={loading}
                spellCheck={false}
                autoComplete="off"
                maxLength={2048}
                aria-label="URL to scan"
              />
              {url && (
                <button
                  onClick={() => { setUrl(''); setResult(null); setError(''); inputRef.current?.focus(); }}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors"
                  aria-label="Clear input"
                >
                  <XCircle size={16} />
                </button>
              )}
            </div>
            <button
              id="scan-btn"
              onClick={handleScan}
              disabled={loading || !url.trim()}
              className="btn-primary shrink-0"
            >
              {loading ? (
                <><Loader2 size={18} className="animate-spin" /> Analyzing…</>
              ) : (
                <><Scan size={18} /> Analyze</>
              )}
            </button>
          </div>

          {/* Privacy Toggle */}
          <div className="flex items-center gap-2 pt-1 text-xs text-slate-400">
            <input
              type="checkbox"
              id="anon-check"
              checked={anonymize}
              onChange={e => setAnonymize(e.target.checked)}
              className="rounded bg-slate-900 border-slate-700 text-blue-500 focus:ring-0 cursor-pointer"
            />
            <label htmlFor="anon-check" className="flex items-center gap-1.5 cursor-pointer select-none">
              <EyeOff size={13} className="text-slate-400" />
              <span>Anonymize scan history (store domain + SHA-256 hash only, strip paths/tokens)</span>
            </label>
          </div>

          {error && !isOffline && (
            <div className="flex items-start gap-2.5 p-3 rounded-lg text-sm bg-red-950/20 border border-red-500/25 text-red-400">
              <AlertTriangle size={16} className="shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {/* Try an example */}
          <div className="space-y-2 pt-2 border-t border-slate-800/80">
            <div className="text-xs font-semibold text-slate-400">
              Try an example (Made-up test URLs · never visited):
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <div className="space-y-1.5">
                <div className="text-[11px] font-medium text-emerald-400 flex items-center gap-1">
                  <CheckCircle size={12} /> Safe-looking examples:
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {[
                    { label: 'Uni Portal', url: 'https://secure-portal.example-university.edu/student/login' },
                    { label: 'Company Docs', url: 'https://internal-docs.mycompany-cloud.org/handbook' },
                    { label: 'Open Source', url: 'https://community-hub.opensource-foundation.net/projects' },
                  ].map(ex => (
                    <button
                      key={ex.label}
                      type="button"
                      onClick={() => { setUrl(ex.url); setResult(null); setError(''); }}
                      className="text-xs px-2.5 py-1 rounded font-mono transition-colors bg-emerald-500/10 text-emerald-300 border border-emerald-500/20 hover:bg-emerald-500/20 truncate max-w-full"
                      title={ex.url}
                    >
                      {ex.label}
                    </button>
                  ))}
                </div>
              </div>
              <div className="space-y-1.5">
                <div className="text-[11px] font-medium text-red-400 flex items-center gap-1">
                  <AlertTriangle size={12} /> Suspicious-looking examples:
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {[
                    { label: 'PayPal Spoof', url: 'https://paypal.com.account-verification-service.xyz/secure/login' },
                    { label: 'IP Host + Port', url: 'http://192.168.1.105:8080/appleid/verify-identity-confirm' },
                    { label: 'Bank Spoof', url: 'https://secure-chase-update.bank.com-verify.net/auth/portal' },
                  ].map(ex => (
                    <button
                      key={ex.label}
                      type="button"
                      onClick={() => { setUrl(ex.url); setResult(null); setError(''); }}
                      className="text-xs px-2.5 py-1 rounded font-mono transition-colors bg-red-500/10 text-red-300 border border-red-500/20 hover:bg-red-500/20 truncate max-w-full"
                      title={ex.url}
                    >
                      {ex.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Batch Scanner Mode Panel */}
      {showBatch && (
        <div className="glass-card p-6 space-y-4 animate-fade-in">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-sm font-semibold text-white">
              <FileSpreadsheet size={16} className="text-teal-400" />
              <span>Batch Scanner (Up to 100 URLs)</span>
            </div>
            <label className="btn-ghost text-xs cursor-pointer flex items-center gap-1 border border-slate-700">
              <Upload size={13} />
              <span>Upload CSV / TXT</span>
              <input type="file" accept=".csv,.txt" onChange={handleFileUpload} className="hidden" />
            </label>
          </div>

          <p className="text-xs text-slate-400">
            Paste one URL per line or upload a file containing URLs in the first column.
          </p>

          <textarea
            value={batchInput}
            onChange={e => setBatchInput(e.target.value)}
            placeholder="https://example1.com&#10;https://paypal.com.evil.xyz/login&#10;https://google.com"
            rows={5}
            className="input-cyber w-full font-mono text-xs"
            disabled={batchLoading}
          />

          <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <input
                type="checkbox"
                id="batch-anon-check"
                checked={anonymize}
                onChange={e => setAnonymize(e.target.checked)}
                className="rounded bg-slate-900 border-slate-700 text-blue-500 cursor-pointer"
              />
              <label htmlFor="batch-anon-check" className="cursor-pointer">
                Anonymize stored URLs
              </label>
            </div>

            <button
              onClick={handleBatchScan}
              disabled={batchLoading || !batchInput.trim()}
              className="btn-primary text-xs"
            >
              {batchLoading ? <><Loader2 size={14} className="animate-spin" /> Processing Batch…</> : <><Scan size={14} /> Scan Batch</>}
            </button>
          </div>

          {batchError && (
            <div className="p-3 rounded-lg text-xs bg-red-950/20 border border-red-500/25 text-red-400">
              {batchError}
            </div>
          )}

          {/* Batch Results Output */}
          {batchResult && (
            <div className="space-y-4 pt-3 border-t border-slate-800">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3 text-xs">
                  <span className="font-semibold text-white">Processed: {batchResult.total} URLs</span>
                  <span className="text-emerald-400">Safe: {batchResult.summary.safe_count}</span>
                  <span className="text-red-400">Phishing: {batchResult.summary.phishing_count}</span>
                  {batchResult.summary.error_count > 0 && (
                    <span className="text-amber-400">Errors: {batchResult.summary.error_count}</span>
                  )}
                </div>
                <button
                  onClick={handleDownloadCsv}
                  className="btn-ghost text-xs text-teal-400 flex items-center gap-1 border border-teal-500/30"
                >
                  <Download size={13} />
                  <span>Download Results CSV</span>
                </button>
              </div>

              <div className="max-h-60 overflow-y-auto space-y-1.5 pr-1">
                {batchResult.results.map((r, i) => (
                  <div key={i} className="flex items-center justify-between p-2 rounded bg-slate-900/60 border border-slate-800 text-xs font-mono">
                    <span className="truncate max-w-[60%] text-slate-300" title={r.url}>{r.url}</span>
                    <div className="flex items-center gap-2 shrink-0">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${r.prediction === 'PHISHING' ? 'bg-red-500/20 text-red-400' : 'bg-emerald-500/20 text-emerald-400'}`}>
                        {r.prediction ?? 'ERROR'}
                      </span>
                      <span className="text-slate-400 text-[11px]">
                        {r.confidence !== null && r.confidence !== undefined ? `${r.confidence.toFixed(1)}%` : 'N/A'}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Loading Skeleton */}
      {loading && (
        <div className="glass-card p-8 space-y-4 animate-pulse">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-slate-800" />
            <div className="space-y-2 flex-1">
              <div className="h-5 bg-slate-800 rounded w-1/3" />
              <div className="h-3 bg-slate-800/60 rounded w-1/4" />
            </div>
          </div>
          <div className="h-10 bg-slate-800/40 rounded-lg" />
          <div className="h-3 bg-slate-800/50 rounded w-full" />
        </div>
      )}

      {/* Single Scan Result */}
      {result && !loading && (
        <div className="space-y-4 animate-slide-up">
          <div
            className="glass-card p-6 space-y-5"
            style={{
              border: riskCfg ? `1px solid ${riskCfg.border}` : undefined,
              boxShadow: riskCfg ? `0 0 30px ${riskCfg.bg}` : undefined,
            }}
          >
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div
                  className="w-12 h-12 rounded-xl flex items-center justify-center shrink-0"
                  style={{ background: riskCfg?.bg, border: `1px solid ${riskCfg?.border}` }}
                >
                  <RiskIcon size={24} style={{ color: riskCfg?.color }} />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider flex items-center gap-1.5 ${
                      result.prediction === 'PHISHING' ? 'badge-threat' : 'badge-safe'
                    }`}>
                      {result.prediction === 'PHISHING' ? <AlertTriangle size={13} /> : <CheckCircle size={13} />}
                      <span>{result.prediction === 'PHISHING' ? 'PHISHING DETECTED' : 'SAFE (LEGITIMATE)'}</span>
                    </span>
                    <span className="text-xs px-2 py-0.5 rounded bg-slate-800/80 border border-slate-700/60 text-slate-300 font-mono">
                      {riskCfg?.label ?? result.risk_level ?? 'Risk Assessment'}
                    </span>
                  </div>
                  <div className="text-xs font-medium text-slate-400 mt-1">
                    Model: {result.model_name ?? 'LightGBM'} · Version: {result.model_version ?? 'v2.0.0'}
                  </div>
                </div>
              </div>

              {/* Action Buttons: Copy URL & Copy Result */}
              <div className="flex items-center gap-2 shrink-0">
                <button
                  id="copy-url-btn"
                  onClick={handleCopyUrl}
                  className="btn-ghost text-xs flex items-center gap-1.5 border border-slate-700/60"
                  title="Copy submitted URL to clipboard"
                  aria-label="Copy URL"
                >
                  {copiedUrl ? <><Check size={14} className="text-emerald-400" /> Copied URL</> : <><Copy size={14} /> Copy URL</>}
                </button>
                <button
                  id="copy-result-btn"
                  onClick={handleCopyResult}
                  className="btn-ghost text-xs flex items-center gap-1.5 border border-slate-700/60"
                  title="Copy formatted plain-text result summary"
                  aria-label="Copy Result"
                >
                  {copiedResult ? <><Check size={14} className="text-emerald-400" /> Copied Summary</> : <><Copy size={14} /> Copy Result</>}
                </button>
              </div>
            </div>

            {/* URL Display: strictly non-link, monospace, wrapped, selectable */}
            <div className="px-3.5 py-3 rounded-lg bg-slate-950/80 border border-slate-800/80">
              <div className="text-[11px] text-slate-500 uppercase tracking-wider mb-1 font-semibold">Analyzed Target URL (Text Only — Never Visited)</div>
              <div className="font-mono text-xs md:text-sm text-cyan-300 break-all select-all whitespace-pre-wrap leading-relaxed">
                {result.url}
              </div>
            </div>

            {/* 4-Stat Metric Summary: Confidence, Phishing Prob, Threshold, Risk Level */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-1">
              <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                <div className="text-[11px] text-slate-500 uppercase tracking-wider font-semibold">Calibrated Confidence</div>
                <div className="text-lg font-bold text-white mt-0.5">
                  {result.confidence !== null && result.confidence !== undefined ? `${result.confidence.toFixed(1)}%` : '—'}
                </div>
              </div>
              <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                <div className="text-[11px] text-slate-500 uppercase tracking-wider font-semibold">Phishing Probability</div>
                <div className="text-lg font-bold text-amber-400 mt-0.5">
                  {result.phishing_probability !== null && result.phishing_probability !== undefined
                    ? `${(result.phishing_probability * 100).toFixed(1)}%`
                    : (result.score !== null && result.score !== undefined ? `${(result.score * 100).toFixed(1)}%` : '—')}
                </div>
              </div>
              <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                <div className="text-[11px] text-slate-500 uppercase tracking-wider font-semibold">Decision Threshold</div>
                <div className="text-lg font-bold text-violet-400 mt-0.5 font-mono">
                  {result.threshold !== undefined && result.threshold !== null ? result.threshold.toFixed(4) : '0.5000'}
                </div>
              </div>
              <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                <div className="text-[11px] text-slate-500 uppercase tracking-wider font-semibold">Risk Level</div>
                <div className="text-lg font-bold mt-0.5" style={{ color: riskCfg?.color ?? '#94a3b8' }}>
                  {result.risk_level ?? 'LOW'}
                </div>
              </div>
            </div>

            {/* Calibrated Confidence & Score Bar */}
            <ScoreBar
              confidence={result.confidence ?? (result.score ? result.score * 100 : null)}
              prediction={result.prediction}
              threshold={result.threshold}
            />
          </div>

          {/* Explain this Result */}
          <ExplanationSection result={result} />

          {/* Risk Indicators */}
          {result.indicators && result.indicators.length > 0 && (
            <div className="glass-card p-5 space-y-3">
              <div className="section-title text-sm font-semibold">
                <AlertTriangle size={18} className="text-amber-400" />
                <span>Detected Risk Indicators ({result.indicators.length})</span>
              </div>
              <ul className="space-y-2">
                {result.indicators.map((ind, i) => (
                  <li key={i} className="flex items-start gap-2.5 text-xs text-amber-300">
                    <span className="w-1.5 h-1.5 rounded-full mt-1.5 shrink-0 bg-amber-400" />
                    <span>{ind}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* 36 Features Detailed View */}
          <div className="glass-card overflow-hidden">
            <button
              onClick={() => setShowFeatures(s => !s)}
              className="w-full flex items-center justify-between px-5 py-3.5 text-sm font-medium text-slate-300 hover:text-white transition-colors"
              aria-expanded={showFeatures}
            >
              <div className="flex items-center gap-2">
                <Info size={16} className="text-blue-400" />
                <span>Extracted Feature Values ({Object.keys(result.features ?? {}).length} features)</span>
              </div>
              {showFeatures ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
            </button>
            {showFeatures && (
              <div className="px-5 pb-5 border-t border-slate-800">
                <p className="text-xs text-slate-400 mt-3 mb-3">
                  These 36 structural metrics are extracted purely from the URL string without visiting the host.
                  Highlighted values indicate active risk features.
                </p>
                <FeatureTable features={result.features} />
              </div>
            )}
          </div>

          {/* Visible Disclaimer */}
          <div className="flex items-start gap-3 px-4 py-3.5 rounded-xl text-xs text-slate-400 bg-slate-900/60 border border-slate-800">
            <Info size={16} className="shrink-0 mt-0.5 text-blue-400" />
            <div className="space-y-0.5">
              <div>
                <strong className="text-slate-300">Disclaimer: </strong>
                URL-only estimate, not a guarantee.
              </div>
              <p className="text-slate-500 text-[11px]">
                {result.disclaimer || 'Predictions are derived purely from structural and lexical patterns without connecting to the remote host. Do not treat this as definitive security assurance.'}
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
