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
  ExternalEvalResponse,
} from '../types/api';

const BASE = '/api';

async function request<T>(
  path: string,
  options?: RequestInit
): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${BASE}${path}`, {
      headers: { 'Content-Type': 'application/json', ...(options?.headers ?? {}) },
      ...options,
    });
  } catch (err: unknown) {
    const rawMsg = err instanceof Error ? err.message : 'Network connection failure';
    throw new Error(`Backend not reachable (${rawMsg}). Start it with python -m backend.app`);
  }

  const json = await res.json().catch(() => ({ error: 'Invalid JSON response from server' }));

  if (!res.ok) {
    let msg = (json as { error?: string }).error;
    if (!msg) {
      if (res.status === 429) {
        msg = 'Rate limit exceeded (too many requests). Please wait a moment before trying again.';
      } else if (res.status === 413) {
        msg = 'Request payload too large. Please reduce the size or count of submitted URLs.';
      } else if (res.status === 503) {
        msg = 'Backend service is currently unavailable or the model is loading. Start it with python -m backend.app';
      } else {
        msg = `HTTP ${res.status}: ${res.statusText || 'Request failed'}`;
      }
    } else {
      if (res.status === 429) {
        msg = `Rate limit reached: ${msg}. Please wait before making more requests.`;
      }
    }
    const error = new Error(msg);
    (error as Error & { status: number }).status = res.status;
    throw error;
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

export async function clearHistory(apiKey?: string): Promise<{ message: string; deleted_count: number }> {
  return request(`/history`, {
    method: 'DELETE',
    headers: apiKey ? { 'x-api-key': apiKey } : {},
  });
}

// ── Model ─────────────────────────────────────────────────────────────────
export async function fetchModelMetrics(): Promise<ModelMetricsResponse> {
  return request<ModelMetricsResponse>('/model-metrics');
}

export async function fetchModelInfo(): Promise<ModelInfoResponse> {
  return request<ModelInfoResponse>('/model-info');
}

export async function fetchExternalEval(): Promise<ExternalEvalResponse | null> {
  return request<ExternalEvalResponse>('/external-eval').catch(() => null);
}
