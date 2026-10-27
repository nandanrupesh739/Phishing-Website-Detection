import React from 'react';
import { Inbox } from 'lucide-react';

interface EmptyStateProps {
  icon?: React.ReactNode;
  title: string;
  description: string;
  action?: {
    label: string;
    onClick: () => void;
  };
  className?: string;
}

export function EmptyState({
  icon,
  title,
  description,
  action,
  className = '',
}: EmptyStateProps) {
  return (
    <div
      className={`glass-card p-10 flex flex-col items-center text-center max-w-md mx-auto ${className}`}
      role="status"
    >
      <div className="w-14 h-14 rounded-2xl flex items-center justify-center mb-4 bg-slate-800/60 border border-slate-700/60 text-slate-400">
        {icon || <Inbox size={26} className="text-slate-400" />}
      </div>
      <h3 className="text-base font-bold text-white mb-1.5">{title}</h3>
      <p className="text-slate-400 text-sm mb-5 leading-relaxed">{description}</p>
      {action && (
        <button
          onClick={action.onClick}
          className="btn-primary text-xs px-4 py-2"
        >
          {action.label}
        </button>
      )}
    </div>
  );
}

export default EmptyState;
