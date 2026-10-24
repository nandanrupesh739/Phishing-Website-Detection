import { useState, useRef } from 'react';
import {
  Scan, AlertTriangle, CheckCircle, XCircle, Copy, Check,
  Shield, Info, ChevronDown, ChevronUp, Loader2, Link2
} from 'lucide-react';
import { predictUrl } from '../services/api';
import type { PredictionResult } from '../types/api';

const RISK_CONFIG = {
  CRITICAL: { label: 'Critical Risk', color: '#ef4444', bg: 'rgba(239,68,68,0.08)', border: 'rgba(239,68,68,0.3)', icon: XCircle },
  HIGH:     { label: 'High Risk',     color: '#f97316', bg: 'rgba(249,115,22,0.08)', border: 'rgba(249,115,22,0.3)', icon: AlertTriangle },
  MEDIUM:   { label: 'Medium Risk',   color: '#f59e0b', bg: 'rgba(245,158,11,0.08)', border: 'rgba(245,158,11,0.3)', icon: AlertTriangle },
  LOW:      { label: 'Low Risk',      color: '#10b981', bg: 'rgba(16,185,129,0.08)', border: 'rgba(16,185,129,0.3)', icon: CheckCircle },
};

function ScoreBar({ score, prediction }: { score: number | null; prediction: string | null }) {
  if (score === null) return null;
  const pct = Math.round(score * 100);
  const isPhishing = prediction === 'PHISHING';
  const color = isPhishing
    ? (pct >= 80 ? '#ef4444' : pct >= 60 ? '#f97316' : '#f59e0b')
    : '#10b981';

  return (
    <div className="space-y-1.5">
      <div className="flex justify-between text-xs text-slate-400">
        <span>Model Confidence</span>
        <span className="font-mono font-semibold" style={{ color }}>{pct}%</span>
      </div>
      <div className="h-2 rounded-full bg-slate-800 overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-700 ease-out"
          style={{ width: `${pct}%`, background: color, boxShadow: `0 0 8px ${color}60` }}
        />
      </div>
      <p className="text-xs text-slate-500">
        Model probability estimate — not a verified security score
      </p>
    </div>
  );
}

function FeatureTable({ features }: { features: Record<string, number> }) {
  const [expanded, setExpanded] = useState(false);
  const entries = Object.entries(features);
  const visible = expanded ? entries : entries.slice(0, 8);

  return (
    <div className="space-y-2">
      <div className="grid grid-cols-2 gap-1">
        {visible.map(([key, val]) => (
          <div key={key} className="flex justify-between items-center px-2.5 py-1.5 rounded-lg bg-navy-900/50 text-xs">
            <span className="text-slate-400 font-mono truncate pr-2">{key.replace(/_/g, ' ')}</span>
            <span className={`font-mono font-semibold shrink-0 ${val > 0 ? 'text-amber-400' : 'text-slate-500'}`}>
              {typeof val === 'number' ? (val % 1 === 0 ? val.toFixed(0) : val.toFixed(3)) : val}
            </span>
          </div>
        ))}
      </div>
      {entries.length > 8 && (
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

export default function Scanner() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<PredictionResult | null>(null);
  const [error, setError] = useState('');
  const [copied, setCopied] = useState(false);
  const [showFeatures, setShowFeatures] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleScan = async () => {
    const trimmed = url.trim();
    if (!trimmed) { setError('Please enter a URL to scan.'); return; }
    if (trimmed.length > 2048) { setError('URL is too long (max 2048 characters).'); return; }

    setError('');
    setLoading(true);
    setResult(null);
    setShowFeatures(false);

    try {
      const res = await predictUrl(trimmed);
      if (res.error) {
        setError(res.error);
      } else {
        setResult(res);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Could not reach the backend. Is Flask running?';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  const handleKey = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') handleScan();
  };

  const handleCopy = () => {
    if (!result) return;
    const text = JSON.stringify({
      url: result.url,
      prediction: result.prediction,
      risk_level: result.risk_level,
      score: result.score,
      indicators: result.indicators,
    }, null, 2);
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  const riskCfg = result?.risk_level ? RISK_CONFIG[result.risk_level as keyof typeof RISK_CONFIG] : null;
  const RiskIcon = riskCfg?.icon ?? Shield;

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-3">
          <div className="p-2 rounded-lg" style={{ background: 'linear-gradient(135deg,rgba(59,130,246,0.2),rgba(139,92,246,0.2))' }}>
            <Scan size={22} className="text-blue-400" />
          </div>
          URL Scanner
        </h1>
        <p className="text-slate-400 text-sm mt-1 ml-11">
          Analyze any URL for phishing indicators using machine learning
        </p>
      </div>

      {/* Input card */}
      <div className="glass-card p-6 space-y-4">
        <div className="flex items-center gap-2 text-sm text-slate-400 mb-1">
          <Link2 size={14} />
          <span>Enter a URL to analyze (e.g. <code className="text-blue-400 font-mono text-xs">http://example.com/login</code>)</span>
        </div>
        <div className="flex gap-3">
          <div className="flex-1 relative">
            <input
              id="url-input"
              ref={inputRef}
              type="text"
              value={url}
              onChange={e => setUrl(e.target.value)}
              onKeyDown={handleKey}
              placeholder="https://example.com/path?param=value"
              className="input-cyber w-full pr-10"
              disabled={loading}
              spellCheck={false}
              autoComplete="off"
              maxLength={2048}
            />
            {url && (
              <button
                onClick={() => { setUrl(''); setResult(null); setError(''); inputRef.current?.focus(); }}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors"
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
              <><Loader2 size={18} className="animate-spin" /> Scanning…</>
            ) : (
              <><Scan size={18} /> Scan</>
            )}
          </button>
        </div>

        {error && (
          <div className="flex items-start gap-2.5 p-3 rounded-lg text-sm"
            style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.25)', color: '#f87171' }}>
            <AlertTriangle size={16} className="shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        {/* Quick examples */}
        <div className="flex flex-wrap gap-2 pt-1">
          <span className="text-xs text-slate-500">Try:</span>
          {[
            'http://192.168.1.1/login',
            'https://bit.ly/phish-test',
            'http://paypa1-verify.com/account',
            'https://www.google.com',
          ].map(ex => (
            <button
              key={ex}
              onClick={() => { setUrl(ex); setResult(null); setError(''); }}
              className="text-xs px-2.5 py-1 rounded-md font-mono transition-colors"
              style={{ background: 'rgba(59,130,246,0.08)', color: '#60a5fa', border: '1px solid rgba(59,130,246,0.15)' }}
            >
              {ex.length > 35 ? ex.slice(0, 35) + '…' : ex}
            </button>
          ))}
        </div>
      </div>

      {/* Loading state */}
      {loading && (
        <div className="glass-card p-10 flex flex-col items-center gap-4 animate-fade-in">
          <div className="relative">
            <div className="w-16 h-16 rounded-full border-2 border-blue-500/20 flex items-center justify-center">
              <Shield size={28} className="text-blue-400" style={{ animation: 'scanPulse 1.5s ease-in-out infinite' }} />
            </div>
            <div className="absolute inset-0 rounded-full border-2 border-blue-500 border-t-transparent animate-spin" />
          </div>
          <div className="text-center">
            <div className="text-white font-semibold">Analyzing URL…</div>
            <div className="text-slate-500 text-sm mt-1">Extracting features and running ML model</div>
          </div>
        </div>
      )}

      {/* Result */}
      {result && !loading && (
        <div className="space-y-4 animate-slide-up">
          {/* Main result card */}
          <div
            className="glass-card p-6 space-y-5"
            style={{
              border: riskCfg ? `1px solid ${riskCfg.border}` : undefined,
              boxShadow: riskCfg ? `0 0 30px ${riskCfg.bg}` : undefined,
            }}
          >
            <div className="flex items-start justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="w-12 h-12 rounded-xl flex items-center justify-center shrink-0"
                  style={{ background: riskCfg?.bg, border: `1px solid ${riskCfg?.border}` }}>
                  <RiskIcon size={24} style={{ color: riskCfg?.color }} />
                </div>
                <div>
                  <div className="text-xl font-bold" style={{ color: riskCfg?.color }}>
                    {result.prediction}
                  </div>
                  <div className="text-sm font-medium text-slate-400 mt-0.5">
                    {riskCfg?.label ?? 'Unknown'} — Model Estimate
                  </div>
                </div>
              </div>
              <button
                id="copy-result-btn"
                onClick={handleCopy}
                className="btn-ghost text-xs shrink-0"
                title="Copy result as JSON"
              >
                {copied ? <><Check size={14} /> Copied</> : <><Copy size={14} /> Copy</>}
              </button>
            </div>

            {/* URL display */}
            <div className="px-3 py-2 rounded-lg" style={{ background: 'rgba(0,0,0,0.3)' }}>
              <div className="text-xs text-slate-500 mb-1">Scanned URL</div>
              <div className="font-mono text-sm text-blue-300 break-all">{result.url}</div>
            </div>

            {/* Score bar */}
            <ScoreBar score={result.score} prediction={result.prediction} />
          </div>

          {/* Indicators */}
          {result.indicators.length > 0 && (
            <div className="glass-card p-5 space-y-3">
              <div className="section-title">
                <AlertTriangle size={18} className="text-amber-400" />
                Risk Indicators ({result.indicators.length})
              </div>
              <ul className="space-y-2">
                {result.indicators.map((ind, i) => (
                  <li key={i} className="flex items-start gap-2.5 text-sm"
                    style={{ color: '#fbbf24' }}>
                    <span className="w-1.5 h-1.5 rounded-full mt-1.5 shrink-0 bg-amber-400" />
                    {ind}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {result.indicators.length === 0 && result.prediction === 'LIKELY LEGITIMATE' && (
            <div className="glass-card p-5 flex items-center gap-3"
              style={{ border: '1px solid rgba(16,185,129,0.2)', background: 'rgba(16,185,129,0.04)' }}>
              <CheckCircle size={20} className="text-emerald-400 shrink-0" />
              <div className="text-sm">
                <div className="text-white font-medium">No suspicious indicators detected</div>
                <div className="text-slate-400 mt-0.5">The URL structure appears consistent with legitimate sites</div>
              </div>
            </div>
          )}

          {/* Features toggle */}
          <div className="glass-card overflow-hidden">
            <button
              onClick={() => setShowFeatures(s => !s)}
              className="w-full flex items-center justify-between px-5 py-3.5 text-sm font-medium text-slate-300 hover:text-white transition-colors"
            >
              <div className="flex items-center gap-2">
                <Info size={16} className="text-blue-400" />
                Extracted Feature Values ({Object.keys(result.features ?? {}).length} features)
              </div>
              {showFeatures ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
            </button>
            {showFeatures && (
              <div className="px-5 pb-5 border-t border-blue-900/20">
                <p className="text-xs text-slate-500 mt-3 mb-3">
                  These are the raw numeric values extracted from the URL structure used by the ML model.
                  Non-zero values (highlighted) indicate detected features.
                </p>
                <FeatureTable features={result.features} />
              </div>
            )}
          </div>

          {/* Disclaimer */}
          <div className="flex items-start gap-3 px-4 py-3.5 rounded-xl text-xs text-slate-400"
            style={{ background: 'rgba(100,116,139,0.08)', border: '1px solid rgba(100,116,139,0.15)' }}>
            <Info size={14} className="shrink-0 mt-0.5 text-slate-500" />
            <p>{result.disclaimer}</p>
          </div>
        </div>
      )}
    </div>
  );
}
