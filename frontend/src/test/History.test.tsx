import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import ScanHistory from '../pages/ScanHistory';
import * as api from '../services/api';

vi.mock('../services/api');

describe('ScanHistory Component - Filtering, Search & Privacy Mode', () => {
  const mockRecords: import('../types/api').ScanRecord[] = [
    {
      id: 1,
      submitted_url: 'https://legit-university.edu/login',
      prediction: 'SAFE',
      risk_level: 'LOW',
      model_score: 0.05,
      score_type: 'calibrated_probability',
      model_version: 'v2.0.0',
      scan_timestamp: '2026-10-27T10:00:00Z',
    },
    {
      id: 2,
      submitted_url: 'https://evil-phish.biz/verify-card',
      prediction: 'PHISHING',
      risk_level: 'CRITICAL',
      model_score: 0.98,
      score_type: 'calibrated_probability',
      model_version: 'v2.0.0',
      scan_timestamp: '2026-10-27T10:15:00Z',
    },
  ];

  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('renders history records and stats accurately', async () => {
    vi.mocked(api.fetchHistory).mockResolvedValue({
      records: mockRecords,
      total: 2,
      limit: 20,
      offset: 0,
      stats: {
        total: 2,
        phishing_count: 1,
        legitimate_count: 1,
        error_count: 0,
      },
    });

    render(<ScanHistory />);

    await waitFor(() => {
      expect(screen.getByText('https://legit-university.edu/login')).toBeInTheDocument();
      expect(screen.getByText('https://evil-phish.biz/verify-card')).toBeInTheDocument();
    });

    // Check stats cards
    expect(screen.getByText('Total Scans')).toBeInTheDocument();
  });

  it('filters records by prediction button (SAFE / PHISHING)', async () => {
    vi.mocked(api.fetchHistory).mockResolvedValue({
      records: mockRecords,
      total: 2,
      limit: 20,
      offset: 0,
      stats: { total: 2, phishing_count: 1, legitimate_count: 1, error_count: 0 },
    });

    render(<ScanHistory />);

    await waitFor(() => {
      expect(screen.getByText('https://legit-university.edu/login')).toBeInTheDocument();
    });

    // Filter by PHISHING only
    const phishBtn = screen.getByRole('button', { name: 'PHISHING' });
    fireEvent.click(phishBtn);

    expect(screen.getByText('https://evil-phish.biz/verify-card')).toBeInTheDocument();
    expect(screen.queryByText('https://legit-university.edu/login')).not.toBeInTheDocument();

    // Filter by SAFE only
    const safeBtn = screen.getByRole('button', { name: 'SAFE' });
    fireEvent.click(safeBtn);

    expect(screen.getByText('https://legit-university.edu/login')).toBeInTheDocument();
    expect(screen.queryByText('https://evil-phish.biz/verify-card')).not.toBeInTheDocument();
  });

  it('filters records by text search input', async () => {
    vi.mocked(api.fetchHistory).mockResolvedValue({
      records: mockRecords,
      total: 2,
      limit: 20,
      offset: 0,
      stats: { total: 2, phishing_count: 1, legitimate_count: 1, error_count: 0 },
    });

    render(<ScanHistory />);

    await waitFor(() => {
      expect(screen.getByText('https://legit-university.edu/login')).toBeInTheDocument();
    });

    const searchInput = screen.getByLabelText(/Search scan history/i);
    fireEvent.change(searchInput, { target: { value: 'evil-phish' } });

    expect(screen.getByText('https://evil-phish.biz/verify-card')).toBeInTheDocument();
    expect(screen.queryByText('https://legit-university.edu/login')).not.toBeInTheDocument();
  });

  it('respects Privacy Mode and labels column "Domain / SHA-256 Hash" when hashes are stored', async () => {
    vi.mocked(api.fetchHistory).mockResolvedValue({
      records: [
        {
          id: 1,
          submitted_url: 'paypal.com [sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08]',
          prediction: 'PHISHING',
          risk_level: 'HIGH',
          model_score: 0.92,
          score_type: 'calibrated_probability',
          model_version: 'v2.0.0',
          scan_timestamp: '2026-10-27T10:00:00Z',
        },
      ],
      total: 1,
      limit: 20,
      offset: 0,
      stats: { total: 1, phishing_count: 1, legitimate_count: 0, error_count: 0 },
    });

    render(<ScanHistory />);

    await waitFor(() => {
      expect(screen.getByText('Domain / SHA-256 Hash')).toBeInTheDocument();
    });

    expect(screen.getByText(/\(Privacy Mode Active\)/i)).toBeInTheDocument();
    expect(screen.queryByText('Submitted URL')).not.toBeInTheDocument();
  });
});
