import React from 'react';
import { AlertTriangle, RefreshCw, Terminal, Clock } from 'lucide-react';

interface ErrorStateProps {
  title?: string;
  message?: string;
  onRetry?: () => void;
  className?: string;
  compact?: boolean;
}

export function ErrorState({
  title = 'Something went wrong',
  message = 'Failed to load data from the server.',
  onRetry,
  className = '',
  compact = false,
}: ErrorStateProps) {
  const isRateLimited = message.toLowerCase().includes('rate limit') || message.includes('429');
  const isOffline =
    message.toLowerCase().includes('failed to fetch') ||
    message.toLowerCase().includes('networkerror') ||
    message.includes('503') ||
    message.toLowerCase().includes('backend');

  if (compact) {
    return (
      <div
        className={`p-3 rounded-lg flex items-center justify-between gap-3 text-xs ${
          isRateLimited
            ? 'bg-amber-950/30 border border-amber-500/30 text-amber-200'
            : 'bg-red-950/30 border border-red-500/30 text-red-200'
        } ${className}`}
        role="alert"
        aria-live="polite"
      >
        <div className="flex items-center gap-2 truncate">
          {isRateLimited ? (
            <Clock size={14} className="text-amber-400 shrink-0" />
          ) : (
            <AlertTriangle size={14} className="text-red-400 shrink-0" />
          )}
          <span className="truncate">{message}</span>
        </div>
        {onRetry && (
          <button
            onClick={onRetry}
            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-white text-[11px] font-semibold shrink-0 flex items-center gap-1 transition-colors"
          >
            <RefreshCw size={11} /> Retry
          </button>
        )}
      </div>
    );
  }

  return (
    <div
      className={`glass-card p-8 flex flex-col items-center text-center max-w-lg mx-auto ${className}`}
      role="alert"
      aria-live="polite"
    >
      <div
        className="w-14 h-14 rounded-2xl flex items-center justify-center mb-4"
        style={{
          background: isRateLimited ? 'rgba(245, 158, 11, 0.12)' : 'rgba(239, 68, 68, 0.12)',
          border: `1px solid ${isRateLimited ? 'rgba(245, 158, 11, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`,
        }}
      >
        {isRateLimited ? (
          <Clock size={28} className="text-amber-400" />
        ) : (
          <AlertTriangle size={28} className="text-red-400" />
        )}
      </div>

      <h3 className="text-lg font-bold text-white mb-2">
        {isRateLimited ? 'Request Rate Limited' : title}
      </h3>

      <p className="text-slate-300 text-sm mb-4 leading-relaxed max-w-sm">
        {isRateLimited
          ? 'You have sent too many requests in a short period (limit: 60/min). Please wait 30 seconds before retrying.'
          : message}
      </p>

      {isOffline && (
        <div className="mb-5 w-full bg-slate-950/80 border border-slate-800 rounded-lg p-3 text-left font-mono text-xs text-slate-300 space-y-1">
          <div className="text-slate-500 text-[10px] uppercase font-bold tracking-wider flex items-center gap-1">
            <Terminal size={12} className="text-cyan-400" /> Start Backend Command:
          </div>
          <div className="text-cyan-300 select-all font-semibold">python -m backend.app</div>
        </div>
      )}

      {onRetry && (
        <button
          onClick={onRetry}
          className="btn-primary flex items-center gap-2 text-sm px-5 py-2.5"
        >
          <RefreshCw size={15} />
          <span>Retry Request</span>
        </button>
      )}
    </div>
  );
}

export default ErrorState;
