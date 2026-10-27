import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import Scanner from '../pages/Scanner';
import * as api from '../services/api';

vi.mock('../services/api');

// Mock recharts ResponsiveContainer to avoid SVG size issues in JSDOM
vi.mock('recharts', async () => {
  const actual: any = await vi.importActual('recharts');
  return {
    ...actual,
    ResponsiveContainer: ({ children }: any) => <div data-testid="responsive-container">{children}</div>,
  };
});

describe('Scanner Page - Validation and Result Rendering', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('validates URL scheme in browser and rejects invalid schemes inline without API call', async () => {
    const predictSpy = vi.mocked(api.predictUrl);

    render(<Scanner />);

    const input = screen.getByLabelText(/Target URL to scan/i);
    const scanBtn = screen.getByRole('button', { name: /Analyze URL/i });

    // Enter invalid scheme (javascript:)
    fireEvent.change(input, { target: { value: 'javascript:alert(1)' } });
    fireEvent.click(scanBtn);

    expect(screen.getByText(/Only http:\/\/ and https:\/\/ URLs are permitted/i)).toBeInTheDocument();
    expect(predictSpy).not.toHaveBeenCalled();

    // Enter invalid scheme (ftp:)
    fireEvent.change(input, { target: { value: 'ftp://ftp.example.com/files' } });
    fireEvent.click(scanBtn);

    expect(screen.getByText(/Only http:\/\/ and https:\/\/ URLs are permitted/i)).toBeInTheDocument();
    expect(predictSpy).not.toHaveBeenCalled();
  });

  it('validates max URL length (> 2048 chars) inline', async () => {
    const predictSpy = vi.mocked(api.predictUrl);

    render(<Scanner />);

    const input = screen.getByLabelText(/Target URL to scan/i);
    const scanBtn = screen.getByRole('button', { name: /Analyze URL/i });

    const hugeUrl = 'https://example.com/' + 'a'.repeat(2050);
    fireEvent.change(input, { target: { value: hugeUrl } });
    fireEvent.click(scanBtn);

    expect(screen.getByText(/exceeds 2048 characters maximum limit/i)).toBeInTheDocument();
    expect(predictSpy).not.toHaveBeenCalled();
  });

  it('renders prediction badge, confidence %, risk, and non-link URL safely', async () => {
    vi.mocked(api.predictUrl).mockResolvedValue({
      url: 'https://paypal-security-update.xyz/login',
      prediction: 'PHISHING',
      risk_level: 'CRITICAL',
      score: 0.985,
      score_type: 'calibrated_probability',
      confidence: 98.5,
      confidence_str: '98.5%',
      phishing_probability: 0.985,
      threshold: 0.5,
      model_name: 'LightGBM',
      model_version: 'v2.0.0',
      indicators: ['Brand impersonation token', 'Suspicious TLD'],
      explanation: [
        { feature: 'brand_impersonation', contribution: 0.45, direction: 'PHISHING' },
      ],
      features: {},
      disclaimer: 'URL-only estimate based on structural features. Never visit suspicious links.',
    });

    render(<Scanner />);

    const input = screen.getByLabelText(/Target URL to scan/i);
    const scanBtn = screen.getByRole('button', { name: /Analyze URL/i });

    fireEvent.change(input, { target: { value: 'https://paypal-security-update.xyz/login' } });
    fireEvent.click(scanBtn);

    await waitFor(() => {
      expect(screen.getByText(/PHISHING DETECTED/i)).toBeInTheDocument();
    });

    // Check calibrated confidence and risk
    expect(screen.getAllByText('98.5%').length).toBeGreaterThan(0);
    expect(screen.getByText(/Critical Risk/i)).toBeInTheDocument();

    // Check model version and threshold
    expect(screen.getByText(/Model: LightGBM · Version: v2.0.0/i)).toBeInTheDocument();
    expect(screen.getAllByText(/0.500/i).length).toBeGreaterThan(0);

    // Check copy buttons
    expect(screen.getByRole('button', { name: /Copy URL/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Copy Result/i })).toBeInTheDocument();

    // Check disclaimer
    expect(screen.getByText(/URL-only estimate, not a guarantee/i)).toBeInTheDocument();

    // CRITICAL: Ensure the target URL is NEVER rendered as a clickable <a> link
    const links = document.querySelectorAll('a');
    links.forEach(link => {
      expect(link.getAttribute('href')).not.toBe('https://paypal-security-update.xyz/login');
    });
  });

  it('populates example URL into the input when example button is clicked', () => {
    render(<Scanner />);

    const exampleBtn = screen.getByRole('button', { name: 'Uni Portal' });
    fireEvent.click(exampleBtn);

    const input = screen.getByLabelText(/Target URL to scan/i) as HTMLInputElement;
    expect(input.value).toBe('https://secure-portal.example-university.edu/student/login');
  });
});
