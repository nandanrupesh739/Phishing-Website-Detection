/**
 * PhishGuard AI — API Service Layer
 * All backend communication is centralised here.
 * The Vite dev server proxies /api → http://127.0.0.1:5000.
 */

import type {
  HealthResponse,
  HistoryResponse,
  ModelInfoResponse,
  ModelMetricsResponse,
  PredictionResult,
} from '../types/api';

const BASE = '/api';

async function request<T>(
  path: string,
  options?: RequestInit
): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...(options?.headers ?? {}) },
    ...options,
  });

  const json = await res.json().catch(() => ({ error: 'Invalid JSON response' }));

  if (!res.ok) {
    const msg = (json as { error?: string }).error ?? `HTTP ${res.status}`;
    throw new Error(msg);
  }

  return json as T;
}

// ── Health ────────────────────────────────────────────────────────────────
export async function fetchHealth(): Promise<HealthResponse> {
  return request<HealthResponse>('/health');
}

// ── Predict ───────────────────────────────────────────────────────────────
export async function predictUrl(url: string, anonymize?: boolean): Promise<PredictionResult> {
  return request<PredictionResult>('/predict', {
    method: 'POST',
    body: JSON.stringify({ url, anonymize }),
  });
}

export async function predictBatch(
  urls: string[],
  anonymize?: boolean
): Promise<import('../types/api').BatchPredictionResponse> {
  return request<import('../types/api').BatchPredictionResponse>('/predict-batch', {
    method: 'POST',
    body: JSON.stringify({ urls, anonymize }),
  });
}

// ── History ───────────────────────────────────────────────────────────────
export async function fetchHistory(
  limit = 50,
  offset = 0
): Promise<HistoryResponse> {
  return request<HistoryResponse>(`/history?limit=${limit}&offset=${offset}`);
}

export async function clearHistory(): Promise<{ message: string; deleted_count: number }> {
  return request(`/history`, { method: 'DELETE' });
}

// ── Model ─────────────────────────────────────────────────────────────────
export async function fetchModelMetrics(): Promise<ModelMetricsResponse> {
  return request<ModelMetricsResponse>('/model-metrics');
}

export async function fetchModelInfo(): Promise<ModelInfoResponse> {
  return request<ModelInfoResponse>('/model-info');
}
