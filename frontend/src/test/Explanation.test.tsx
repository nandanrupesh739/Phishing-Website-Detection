import { render, screen } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { ExplanationSection } from '../pages/Scanner';
import type { PredictionResult } from '../types/api';

// Mock recharts ResponsiveContainer to avoid SVG dimensions issues in jsdom
vi.mock('recharts', async () => {
  const actual: any = await vi.importActual('recharts');
  return {
    ...actual,
    ResponsiveContainer: ({ children }: any) => <div data-testid="responsive-container">{children}</div>,
  };
});

describe('ExplanationSection Component ("Why this result?")', () => {
  it('renders correctly with top 5 feature contributions and indicators', () => {
    const mockResultWithData: PredictionResult = {
      url: 'https://paypal.com.account-update.xyz/login',
      prediction: 'PHISHING',
      risk_level: 'HIGH',
      score: 0.985,
      score_type: 'calibrated_probability',
      confidence: 98.5,
      threshold: 0.95,
      explanation: [
        { feature: 'has_brand_impersonation', contribution: 0.42, direction: 'PHISHING' },
        { feature: 'has_suspicious_tld', contribution: 0.28, direction: 'PHISHING' },
        { feature: 'domain_digit_count', contribution: 0.15, direction: 'PHISHING' },
        { feature: 'vowel_consonant_ratio', contribution: -0.05, direction: 'SAFE' },
        { feature: 'path_depth', contribution: 0.08, direction: 'PHISHING' },
      ],
      indicators: [
        'Brand name detected in path/subdomain',
        'Abused suspicious TLD (.xyz)',
      ],
      features: {},
      disclaimer: 'URL-only estimate, not a guarantee.',
    };

    render(<ExplanationSection result={mockResultWithData} />);

    // Header and Disclaimer
    expect(screen.getByText(/Why this result\?/i)).toBeInTheDocument();
    expect(screen.getByText(/Model Behaviour Explanation:/i)).toBeInTheDocument();
    expect(
      screen.getByText(/This represents an explanation of the machine learning model's behaviour, not legal or definitive forensic proof/i)
    ).toBeInTheDocument();

    // Chart container
    expect(screen.getByTestId('responsive-container')).toBeInTheDocument();
    expect(screen.getByText('Top Contributing Features:')).toBeInTheDocument();

    // Indicators
    expect(screen.getByText(/Observed Heuristic Indicators \(2\)/i)).toBeInTheDocument();
    expect(screen.getByText('Brand name detected in path/subdomain')).toBeInTheDocument();
    expect(screen.getByText('Abused suspicious TLD (.xyz)')).toBeInTheDocument();
  });

  it('renders graceful fallback when no explanation data is present', () => {
    const mockResultNoData: PredictionResult = {
      url: 'https://clean-example.com',
      prediction: 'SAFE',
      risk_level: 'LOW',
      score: 0.01,
      score_type: 'calibrated_probability',
      confidence: 99.0,
      threshold: 0.95,
      explanation: [],
      feature_contributions: [],
      indicators: [],
      features: {},
      disclaimer: 'URL-only estimate, not a guarantee.',
    };

    render(<ExplanationSection result={mockResultNoData} />);

    expect(screen.getByText(/Why this result\?/i)).toBeInTheDocument();
    expect(screen.getByText(/No feature attribution data available for this prediction/i)).toBeInTheDocument();
  });
});
