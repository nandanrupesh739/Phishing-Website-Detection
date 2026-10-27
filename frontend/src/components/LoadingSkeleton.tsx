import React from 'react';

interface LoadingSkeletonProps {
  type?: 'card' | 'table' | 'chart' | 'lines';
  count?: number;
  className?: string;
  height?: string | number;
}

export function LoadingSkeleton({
  type = 'card',
  count = 1,
  className = '',
  height,
}: LoadingSkeletonProps) {
  const items = Array.from({ length: count });

  if (type === 'card') {
    return (
      <div className={`grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 ${className}`}>
        {items.map((_, i) => (
          <div
            key={i}
            className="glass-card p-5 space-y-3 animate-pulse"
            role="status"
            aria-label="Loading metric"
          >
            <div className="h-3 w-24 bg-slate-800 rounded" />
            <div className="h-8 w-32 bg-slate-800/80 rounded" />
            <div className="h-2.5 w-full bg-slate-800/50 rounded" />
          </div>
        ))}
      </div>
    );
  }

  if (type === 'table') {
    return (
      <div className={`glass-card overflow-hidden divide-y divide-slate-800/60 ${className}`} role="status">
        <div className="p-4 bg-slate-900/60 flex gap-4">
          <div className="h-4 w-28 bg-slate-800 rounded animate-pulse" />
          <div className="h-4 w-20 bg-slate-800 rounded animate-pulse" />
          <div className="h-4 w-16 bg-slate-800 rounded animate-pulse" />
        </div>
        {items.map((_, i) => (
          <div key={i} className="p-4 flex gap-4 animate-pulse items-center">
            <div className="h-4 w-1/3 bg-slate-800/70 rounded" />
            <div className="h-4 w-24 bg-slate-800/50 rounded" />
            <div className="h-6 w-16 bg-slate-800/60 rounded-full" />
            <div className="h-4 w-20 ml-auto bg-slate-800/40 rounded" />
          </div>
        ))}
      </div>
    );
  }

  if (type === 'chart') {
    return (
      <div
        className={`glass-card p-6 flex flex-col justify-between animate-pulse ${className}`}
        style={{ height: height || 280 }}
        role="status"
        aria-label="Loading chart"
      >
        <div className="flex justify-between items-center mb-4">
          <div className="h-4 w-32 bg-slate-800 rounded" />
          <div className="h-3 w-20 bg-slate-800/60 rounded" />
        </div>
        <div className="flex-1 flex items-end gap-3 pb-2 pt-6">
          {Array.from({ length: 8 }).map((_, i) => (
            <div
              key={i}
              className="flex-1 bg-slate-800/60 rounded-t"
              style={{ height: `${20 + ((i * 19) % 75)}%` }}
            />
          ))}
        </div>
        <div className="h-3 w-full bg-slate-800/40 rounded mt-2" />
      </div>
    );
  }

  // Default: lines
  return (
    <div className={`space-y-2.5 animate-pulse ${className}`} role="status" aria-label="Loading content">
      {items.map((_, i) => (
        <div
          key={i}
          className="h-4 bg-slate-800/70 rounded"
          style={{ width: `${85 - ((i * 13) % 40)}%` }}
        />
      ))}
    </div>
  );
}

export default LoadingSkeleton;
