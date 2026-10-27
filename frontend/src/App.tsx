import { useState, useEffect } from 'react';
import {
  Shield, Scan, History, BarChart2, Info, AlertTriangle,
  CheckCircle, Wifi, WifiOff, Menu, X, FileSpreadsheet
} from 'lucide-react';
import { fetchHealth } from './services/api';
import type { HealthResponse } from './types/api';
import Scanner from './pages/Scanner';
import Dashboard from './pages/Dashboard';
import ScanHistory from './pages/ScanHistory';
import ModelPerformance from './pages/ModelPerformance';
import About from './pages/About';
import { ErrorBoundary } from './components/ErrorBoundary';

type Page = 'dashboard' | 'scanner' | 'batch' | 'history' | 'performance' | 'about';

const NAV_ITEMS: { id: Page; label: string; icon: React.ReactNode }[] = [
  { id: 'dashboard',    label: 'Dashboard',        icon: <Shield size={18} /> },
  { id: 'scanner',      label: 'URL Scanner',       icon: <Scan size={18} /> },
  { id: 'batch',        label: 'Batch Scanner',     icon: <FileSpreadsheet size={18} /> },
  { id: 'history',      label: 'Scan History',      icon: <History size={18} /> },
  { id: 'performance',  label: 'Model Performance', icon: <BarChart2 size={18} /> },
  { id: 'about',        label: 'About Project',     icon: <Info size={18} /> },
];

export default function App() {
  const [page, setPage] = useState<Page>('dashboard');
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthError, setHealthError] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  const checkHealth = () => {
    fetchHealth()
      .then(h => {
        setHealth(h);
        setHealthError(false);
      })
      .catch(() => {
        setHealthError(true);
      });
  };

  useEffect(() => {
    checkHealth();
    // Poll /api/health every 30 seconds (Phase 5.1 requirement)
    const interval = setInterval(checkHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  const navigate = (p: Page) => {
    setPage(p);
    setMobileOpen(false);
  };

  // Status dot indicators
  // Green = model ready, Amber = backend up but no model, Red = offline
  const statusColor = healthError
    ? '#ef4444' // red
    : health?.model_available
    ? '#10b981' // green
    : '#f59e0b'; // amber

  const statusLabel = healthError
    ? 'Backend Offline'
    : health?.model_available
    ? `Model Ready (${health.model_name || 'Loaded'})`
    : 'Backend Up (No Model)';

  return (
    <div className="min-h-screen bg-grid flex flex-col" style={{ background: 'var(--bg-primary)' }}>
      {/* ── Offline Banner (Phase 5.1 requirement) ───────────────────── */}
      {healthError && (
        <div
          className="sticky top-0 z-50 px-4 py-2 text-center text-xs font-medium text-red-200 flex items-center justify-center gap-2"
          style={{ background: 'rgba(239, 68, 68, 0.95)', backdropFilter: 'blur(8px)' }}
          role="alert"
          aria-live="polite"
        >
          <WifiOff size={14} className="shrink-0" />
          <span>Backend not reachable, start it with: <code className="font-mono bg-black/40 px-1.5 py-0.5 rounded text-white">python -m backend.app</code></span>
          <button
            onClick={checkHealth}
            className="ml-2 px-2 py-0.5 bg-black/30 hover:bg-black/50 text-white rounded text-[11px] underline"
          >
            Retry
          </button>
        </div>
      )}

      {/* ── Mobile overlay ─────────────────────────────────────────────── */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/60 backdrop-blur-sm lg:hidden"
          onClick={() => setMobileOpen(false)}
        />
      )}

      {/* ── Sidebar ────────────────────────────────────────────────────── */}
      <aside
        className={`fixed top-0 left-0 h-full z-40 w-64 flex flex-col transition-transform duration-300 ${
          mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        }`}
        style={{
          background: 'rgba(6, 14, 39, 0.97)',
          borderRight: '1px solid rgba(59, 130, 246, 0.12)',
          backdropFilter: 'blur(12px)',
        }}
      >
        {/* Logo & Header Status Dot */}
        <div className="flex items-center justify-between px-5 py-5 border-b border-blue-900/30">
          <div className="flex items-center gap-3">
            <div className="relative">
              <div className="w-9 h-9 rounded-lg flex items-center justify-center"
                style={{ background: 'linear-gradient(135deg, #3b82f6, #8b5cf6)' }}>
                <Shield size={20} className="text-white" />
              </div>
              {/* Header Status Dot: Green = model ready, Amber = no model, Red = offline */}
              <div
                className="absolute -top-1 -right-1 w-3 h-3 rounded-full border-2 border-slate-950 transition-colors"
                style={{ background: statusColor }}
                title={statusLabel}
                aria-label={statusLabel}
              />
            </div>
            <div>
              <div className="font-bold text-white text-sm leading-none flex items-center gap-1.5">
                PhishGuard
                <span
                  className="w-2 h-2 rounded-full inline-block"
                  style={{ background: statusColor }}
                  title={statusLabel}
                />
              </div>
              <div className="text-xs font-medium mt-0.5" style={{ color: '#8b5cf6' }}>AI Detection</div>
            </div>
          </div>
          <button
            className="lg:hidden p-1.5 rounded-lg hover:bg-blue-900/20"
            onClick={() => setMobileOpen(false)}
            aria-label="Close navigation menu"
          >
            <X size={18} className="text-slate-400" />
          </button>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-3 py-4 space-y-1">
          {NAV_ITEMS.map(item => (
            <button
              key={item.id}
              id={`nav-${item.id}`}
              onClick={() => navigate(item.id)}
              className={`nav-item w-full text-left ${page === item.id ? 'active' : ''}`}
            >
              {item.icon}
              <span>{item.label}</span>
            </button>
          ))}
        </nav>

        {/* Health status footer widget */}
        <div className="px-4 py-4 border-t border-blue-900/20">
          <div className="glass-card px-3 py-2.5 flex items-center gap-2.5">
            {healthError ? (
              <>
                <WifiOff size={14} className="text-red-400 shrink-0" />
                <div className="min-w-0 flex-1">
                  <div className="text-xs font-medium text-red-400">Backend Offline</div>
                  <div className="text-[11px] text-slate-500 truncate">python -m backend.app</div>
                </div>
              </>
            ) : health ? (
              <>
                {health.model_available ? (
                  <CheckCircle size={14} className="text-emerald-400 shrink-0" />
                ) : (
                  <AlertTriangle size={14} className="text-amber-400 shrink-0" />
                )}
                <div className="min-w-0 flex-1">
                  <div className="text-xs font-medium text-white truncate">
                    {health.model_available ? 'Model Ready' : 'No Model'}
                  </div>
                  <div className="text-[11px] text-slate-500 truncate">
                    {health.model_available ? health.model_name ?? 'LightGBM' : 'Train first'}
                  </div>
                </div>
              </>
            ) : (
              <>
                <Wifi size={14} className="text-slate-500 shrink-0 animate-pulse" />
                <div className="text-xs text-slate-500">Checking status…</div>
              </>
            )}
          </div>
        </div>

        {/* Version */}
        <div className="px-4 pb-4 text-center">
          <span className="text-xs text-slate-600">v2.0.0 — Educational use only</span>
        </div>
      </aside>

      {/* ── Main content area ───────────────────────────────────────────── */}
      <div className="lg:pl-64 min-h-screen flex flex-col flex-1">
        {/* Top bar (mobile) */}
        <header className="lg:hidden sticky top-0 z-20 flex items-center justify-between px-4 py-3 border-b border-blue-900/20"
          style={{ background: 'rgba(6, 14, 39, 0.95)', backdropFilter: 'blur(12px)' }}>
          <button
            id="mobile-menu-btn"
            onClick={() => setMobileOpen(true)}
            className="p-2 rounded-lg hover:bg-blue-900/20"
            aria-label="Open mobile menu"
          >
            <Menu size={20} className="text-slate-400" />
          </button>
          <div className="flex items-center gap-2">
            <Shield size={18} className="text-blue-400" />
            <span className="font-bold text-white text-sm">PhishGuard AI</span>
            <span
              className="w-2 h-2 rounded-full inline-block ml-1"
              style={{ background: statusColor }}
              title={statusLabel}
            />
          </div>
          <div className="w-8" />
        </header>

        {/* Page content with ErrorBoundary wrapping each page (Phase 5.1 requirement) */}
        <main className="flex-1 p-4 md:p-6 lg:p-8 animate-fade-in">
          {page === 'dashboard' && (
            <ErrorBoundary pageName="Dashboard">
              <Dashboard onNavigate={navigate} />
            </ErrorBoundary>
          )}
          {page === 'scanner' && (
            <ErrorBoundary pageName="URL Scanner">
              <Scanner initialTab="single" onSwitchTab={(t: 'single' | 'batch') => { if (t === 'batch') navigate('batch'); }} />
            </ErrorBoundary>
          )}
          {page === 'batch' && (
            <ErrorBoundary pageName="Batch Scanner">
              <Scanner initialTab="batch" onSwitchTab={(t: 'single' | 'batch') => { if (t === 'single') navigate('scanner'); }} />
            </ErrorBoundary>
          )}
          {page === 'history' && (
            <ErrorBoundary pageName="Scan History">
              <ScanHistory />
            </ErrorBoundary>
          )}
          {page === 'performance' && (
            <ErrorBoundary pageName="Model Performance">
              <ModelPerformance />
            </ErrorBoundary>
          )}
          {page === 'about' && (
            <ErrorBoundary pageName="About Project">
              <About />
            </ErrorBoundary>
          )}
        </main>
      </div>
    </div>
  );
}
