import { render, screen, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import ModelPerformance from '../pages/ModelPerformance';
import * as api from '../services/api';

vi.mock('../services/api');

// Mock recharts ResponsiveContainer to avoid SVG dimensions errors in jsdom
vi.mock('recharts', async () => {
  const actual: any = await vi.importActual('recharts');
  return {
    ...actual,
    ResponsiveContainer: ({ children }: any) => <div data-testid="responsive-container">{children}</div>,
  };
});

describe('ModelPerformance Component - Graceful Degradation', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('renders graceful error state when metrics request fails', async () => {
    vi.mocked(api.fetchModelMetrics).mockRejectedValue(new Error('Failed to fetch metrics'));
    vi.mocked(api.fetchModelInfo).mockResolvedValue({
      model_available: false,
    });

    render(<ModelPerformance />);

    await waitFor(() => {
      expect(screen.getByText('No Model Metrics Available')).toBeInTheDocument();
    });
    expect(screen.getByText(/Failed to fetch metrics/i)).toBeInTheDocument();
    expect(screen.getByText('python train.py')).toBeInTheDocument();
  });

  it('renders graceful fallback values ("—" and "unavailable") when metrics fields are null or missing', async () => {
    vi.mocked(api.fetchModelMetrics).mockResolvedValue({
      test_metrics: {
        model_name: 'PartiallyTrainedModel',
        accuracy: null as any,
        precision: undefined as any,
        recall: null as any,
        f1: null as any,
        roc_auc: null,
        average_precision: null,
        confusion_matrix: null as any,
      },
      validation_comparison: undefined,
      feature_importances: undefined,
    });
    vi.mocked(api.fetchModelInfo).mockResolvedValue({
      model_available: true,
      dataset_size: undefined,
      feature_count: undefined,
    });

    render(<ModelPerformance />);

    await waitFor(() => {
      expect(screen.getByText('PartiallyTrainedModel — Evaluated on held-out test set')).toBeInTheDocument();
    });

    // Check for confusion matrix fallback
    expect(screen.getByText('Confusion matrix unavailable')).toBeInTheDocument();

    // Verify no NaN% or undefined% anywhere
    const html = document.body.innerHTML;
    expect(html).not.toContain('NaN%');
    expect(html).not.toContain('undefined%');
    expect(html).toContain('—');
  });
});
