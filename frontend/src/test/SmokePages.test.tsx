import { render, screen, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import Dashboard from '../pages/Dashboard';
import Scanner from '../pages/Scanner';
import ScanHistory from '../pages/ScanHistory';
import ModelPerformance from '../pages/ModelPerformance';
import About from '../pages/About';
import * as api from '../services/api';

vi.mock('../services/api');

// Mock recharts ResponsiveContainer for JSDOM
vi.mock('recharts', async () => {
  const actual: any = await vi.importActual('recharts');
  return {
    ...actual,
    ResponsiveContainer: ({ children }: any) => <div data-testid="responsive-container">{children}</div>,
  };
});

// Normal mock datasets
const mockNormalModelMetrics = {
  test_metrics: {
    model_name: 'CalibratedLightGBM',
    accuracy: 0.9934,
    precision: 1.0,
    recall: 0.9839,
    f1: 0.9919,
    roc_auc: 0.998,
    average_precision: 0.9983,
    brier_score: 0.0042,
    confusion_matrix: [
      [20115, 0],
      [227, 13835],
    ],
  },
  validation_comparison: {
    LightGBM: { accuracy: 0.9958, f1: 0.995 },
  },
  feature_importances: [
    { feature: 'url_length', importance: 0.15 },
    { feature: 'has_suspicious_terms', importance: 0.12 },
  ],
  dataset_source: 'UCI PhiUSIIL',
  dataset_size: 235370,
  label_distribution: { '0': 134850, '1': 100520 },
  decision_threshold: 0.95,
};

const mockNormalModelInfo = {
  model_available: true,
  model_name: 'LightGBM-Sigmoid',
  model_version: '2.0.0',
  feature_count: 42,
  dataset_source: 'UCI PhiUSIIL Phishing Dataset',
  dataset_size: 235370,
  trained_at: '2026-01-01T00:00:00Z',
  decision_threshold: 0.95,
  target_phishing_recall: 0.98,
  split_description: '70/15/15 Domain-Grouped Split',
};

const mockNormalExternalEval = {
  available: true,
  metrics: {
    phishing_recall: 0.88,
    false_positive_rate: 0.02,
    precision: 0.95,
    accuracy: 0.93,
    f1_score: 0.91,
    confusion_matrix: {
      true_positives: 440,
      false_positives: 10,
      true_negatives: 490,
      false_negatives: 60,
    },
  },
};

const mockNormalHistory = {
  records: [
    {
      id: 1,
      submitted_url: 'https://paypal-update.example.com',
      prediction: 'PHISHING',
      risk_level: 'CRITICAL',
      model_score: 0.99,
      score_type: 'calibrated_probability',
      model_version: '2.0.0',
      scan_timestamp: '2026-01-01T12:00:00Z',
    },
  ],
  total: 1,
  limit: 50,
  offset: 0,
  stats: {
    total: 1,
    phishing_count: 1,
    legitimate_count: 0,
    error_count: 0,
  },
};

describe('Smoke Tests — All Pages Render Without Crashing', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  // ────────────────────────────────────────────────────────────────────────
  // (a) Normal Data Mode
  // ────────────────────────────────────────────────────────────────────────
  describe('Mode (a): Normal Data', () => {
    beforeEach(() => {
      vi.mocked(api.fetchModelMetrics).mockResolvedValue(mockNormalModelMetrics as any);
      vi.mocked(api.fetchModelInfo).mockResolvedValue(mockNormalModelInfo as any);
      vi.mocked(api.fetchExternalEval).mockResolvedValue(mockNormalExternalEval as any);
      vi.mocked(api.fetchHistory).mockResolvedValue(mockNormalHistory as any);
    });

    it('renders Dashboard without crash', async () => {
      const { container } = render(<Dashboard onNavigate={() => {}} />);
      await waitFor(() => {
        expect(container).toBeInTheDocument();
      });
      expect(screen.getByText('Analyze a URL Now')).toBeInTheDocument();
    });

    it('renders Scanner without crash', () => {
      const { container } = render(<Scanner />);
      expect(container).toBeInTheDocument();
      expect(screen.getByText(/PhishGuard Scanner/i)).toBeInTheDocument();
    });

    it('renders Batch Scanner tab without crash', () => {
      const { container } = render(<Scanner initialTab="batch" />);
      expect(container).toBeInTheDocument();
      expect(screen.getByText(/Batch Scanner/i)).toBeInTheDocument();
    });

    it('renders ScanHistory without crash', async () => {
      const { container } = render(<ScanHistory />);
      await waitFor(() => {
        expect(container).toBeInTheDocument();
      });
      expect(screen.getByText('Scan History')).toBeInTheDocument();
    });

    it('renders ModelPerformance without crash', async () => {
      const { container } = render(<ModelPerformance />);
      await waitFor(() => {
        expect(container).toBeInTheDocument();
      });
      expect(screen.getByText('Model Performance')).toBeInTheDocument();
    });

    it('renders About without crash', async () => {
      const { container } = render(<About />);
      await waitFor(() => {
        expect(container).toBeInTheDocument();
      });
      expect(screen.getByText('About PhishGuard AI')).toBeInTheDocument();
    });
  });

  // ────────────────────────────────────────────────────────────────────────
  // (b) Empty Data Mode
  // ────────────────────────────────────────────────────────────────────────
  describe('Mode (b): Empty Data', () => {
    beforeEach(() => {
      vi.mocked(api.fetchModelMetrics).mockResolvedValue({
        test_metrics: {} as any,
        validation_comparison: {},
        feature_importances: [],
      } as any);
      vi.mocked(api.fetchModelInfo).mockResolvedValue({
        model_available: false,
      } as any);
      vi.mocked(api.fetchExternalEval).mockResolvedValue({
        available: false,
      } as any);
      vi.mocked(api.fetchHistory).mockResolvedValue({
        records: [],
        total: 0,
        limit: 50,
        offset: 0,
        stats: { total: 0, phishing_count: 0, legitimate_count: 0, error_count: 0 },
      });
    });

    it('renders Dashboard with empty data without crash', async () => {
      const { container } = render(<Dashboard onNavigate={() => {}} />);
      await waitFor(() => {
        expect(container).toBeInTheDocument();
      });
      expect(screen.getByText('Analyze a URL Now')).toBeInTheDocument();
    });

    it('renders Scanner with empty state without crash', () => {
      const { container } = render(<Scanner />);
      expect(container).toBeInTheDocument();
    });

    it('renders Batch Scanner with empty state without crash', () => {
      const { container } = render(<Scanner initialTab="batch" />);
      expect(container).toBeInTheDocument();
    });

    it('renders ScanHistory with empty state without crash', async () => {
      const { container } = render(<ScanHistory />);
      await waitFor(() => {
        expect(screen.getByText(/No scan history yet/i)).toBeInTheDocument();
      });
      expect(container).toBeInTheDocument();
    });

    it('renders ModelPerformance with empty metrics without crash', async () => {
      const { container } = render(<ModelPerformance />);
      await waitFor(() => {
        expect(container).toBeInTheDocument();
      });
      expect(screen.getByText('Model Performance')).toBeInTheDocument();
    });

    it('renders About with empty model info without crash', async () => {
      const { container } = render(<About />);
      await waitFor(() => {
        expect(container).toBeInTheDocument();
      });
      expect(screen.getByText('About PhishGuard AI')).toBeInTheDocument();
    });
  });

  // ────────────────────────────────────────────────────────────────────────
  // (c) Error Mode
  // ────────────────────────────────────────────────────────────────────────
  describe('Mode (c): API Error Failure', () => {
    beforeEach(() => {
      vi.mocked(api.fetchModelMetrics).mockRejectedValue(new Error('Backend not reachable (500)'));
      vi.mocked(api.fetchModelInfo).mockRejectedValue(new Error('Backend not reachable (500)'));
      vi.mocked(api.fetchExternalEval).mockRejectedValue(new Error('Backend not reachable (500)'));
      vi.mocked(api.fetchHistory).mockRejectedValue(new Error('Backend not reachable (500)'));
    });

    it('renders Dashboard gracefully when API fails', async () => {
      const { container } = render(<Dashboard onNavigate={() => {}} />);
      await waitFor(() => {
        expect(container).toBeInTheDocument();
      });
      expect(screen.getByText('Analyze a URL Now')).toBeInTheDocument();
    });

    it('renders Scanner safely when API fails', () => {
      const { container } = render(<Scanner />);
      expect(container).toBeInTheDocument();
    });

    it('renders Batch Scanner safely when API fails', () => {
      const { container } = render(<Scanner initialTab="batch" />);
      expect(container).toBeInTheDocument();
    });

    it('renders ScanHistory error state when API fails', async () => {
      const { container } = render(<ScanHistory />);
      await waitFor(() => {
        expect(screen.getByText(/Failed to Load History/i)).toBeInTheDocument();
      });
      expect(container).toBeInTheDocument();
    });

    it('renders ModelPerformance error state when API fails', async () => {
      render(<ModelPerformance />);
      await waitFor(() => {
        expect(screen.getByText(/No Model Metrics Available/i)).toBeInTheDocument();
      });
    });

    it('renders About page safely when API fails', async () => {
      const { container } = render(<About />);
      await waitFor(() => {
        expect(container).toBeInTheDocument();
      });
      expect(screen.getByText('About PhishGuard AI')).toBeInTheDocument();
    });
  });
});
