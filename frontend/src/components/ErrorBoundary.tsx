import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertOctagon, RotateCcw } from 'lucide-react';

interface Props {
  children: ReactNode;
  pageName?: string;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('ErrorBoundary caught error:', error, errorInfo);
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null });
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div className="max-w-lg mx-auto py-12 px-4" role="alert">
          <div className="glass-card p-8 flex flex-col items-center text-center">
            <div className="w-14 h-14 rounded-2xl flex items-center justify-center mb-4 bg-red-500/10 border border-red-500/30 text-red-400">
              <AlertOctagon size={28} />
            </div>
            <h2 className="text-xl font-bold text-white mb-2">
              {this.props.pageName ? `${this.props.pageName} encountered an error` : 'Page Rendering Error'}
            </h2>
            <p className="text-slate-300 text-sm mb-4 leading-relaxed max-w-sm">
              An unexpected error occurred while displaying this page. The rest of the application remains operational.
            </p>
            {this.state.error && (
              <div className="w-full bg-slate-950/70 border border-slate-800 rounded p-3 mb-5 text-left font-mono text-xs text-red-300 overflow-x-auto">
                {this.state.error.message || String(this.state.error)}
              </div>
            )}
            <div className="flex gap-3">
              <button
                onClick={this.handleReset}
                className="btn-primary flex items-center gap-2 text-sm px-4 py-2"
              >
                <RotateCcw size={15} />
                <span>Try Again</span>
              </button>
              <button
                onClick={() => window.location.reload()}
                className="btn-ghost text-sm px-4 py-2 border border-slate-700"
              >
                Reload Window
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
