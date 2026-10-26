import { render, screen, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import Dashboard from '../pages/Dashboard';
import * as api from '../services/api';

vi.mock('../services/api');

describe('Dashboard Component - Graceful Degradation', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('renders gracefully without crash or NaN when metrics fields are missing', async () => {
    // Mock health ok
    vi.mocked(api.fetchHealth).mockResolvedValue({
      status: 'ok',
      model_available: true,
      model_name: 'LightGBM',
      model_version: '1.0.0',
      feature_count: 36,
    });

    // Mock empty history
    vi.mocked(api.fetchHistory).mockResolvedValue({
      records: [],
      total: 0,
      limit: 5,
      offset: 0,
      stats: {
        total: 0,
        phishing_count: 0,
        legitimate_count: 0,
        error_count: 0,
      },
    });

    // Mock metrics with missing/partial fields
    vi.mocked(api.fetchModelMetrics).mockResolvedValue({
      test_metrics: {
        model_name: 'TestModel',
        // missing accuracy, recall, precision, f1
      } as any,
    });

    render(<Dashboard onNavigate={vi.fn()} />);

    // Expect loading state initially or resolved state
    await waitFor(() => {
      expect(screen.getByText('PhishGuard AI')).toBeInTheDocument();
    });

    // Verify there is NO "NaN%" on screen
    const html = document.body.innerHTML;
    expect(html).not.toContain('NaN%');
    expect(html).not.toContain('undefined%');
  });

  it('renders "No metrics available" when metrics API rejects', async () => {
    vi.mocked(api.fetchHealth).mockResolvedValue({
      status: 'ok',
      model_available: false,
      model_name: null,
      model_version: null,
      feature_count: null,
    });
    vi.mocked(api.fetchHistory).mockResolvedValue({
      records: [],
      total: 0,
      limit: 5,
      offset: 0,
      stats: { total: 0, phishing_count: 0, legitimate_count: 0, error_count: 0 },
    });
    vi.mocked(api.fetchModelMetrics).mockRejectedValue(new Error('Network error'));

    render(<Dashboard onNavigate={vi.fn()} />);

    await waitFor(() => {
      expect(screen.getByText('No metrics available')).toBeInTheDocument();
    });

    expect(screen.getByText('Model not trained yet')).toBeInTheDocument();
  });
});
