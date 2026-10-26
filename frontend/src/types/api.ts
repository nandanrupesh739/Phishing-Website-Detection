/**
 * PhishGuard AI — TypeScript API Types
 * Matches the Flask backend response schemas exactly.
 */

// ── Prediction ────────────────────────────────────────────────────────────

export interface PredictionRequest {
  url: string;
}

export interface PredictionResult {
  url: string;
  prediction: "PHISHING" | "LIKELY LEGITIMATE" | "SAFE" | null;
  risk_level: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | null;
  score: number | null;
  score_type: "model_probability" | "model_score" | "unavailable";
  indicators: string[];
  features: Record<string, number>;
  disclaimer: string;
  error?: string;
}

// ── Health ────────────────────────────────────────────────────────────────

export interface HealthResponse {
  status: "ok" | "error";
  model_available: boolean;
  model_name: string | null;
  model_version: string | null;
  feature_count: number | null;
}

// ── History ───────────────────────────────────────────────────────────────

export interface ScanRecord {
  id: number;
  submitted_url: string;
  prediction: string | null;
  risk_level: string | null;
  model_score: number | null;
  score_type: string | null;
  model_version: string | null;
  scan_timestamp: string;
}

export interface HistoryStats {
  total: number;
  phishing_count: number;
  legitimate_count: number;
  error_count: number;
}

export interface HistoryResponse {
  records: ScanRecord[];
  total: number;
  limit: number;
  offset: number;
  stats: HistoryStats;
}

// ── Model Metrics ─────────────────────────────────────────────────────────

export interface TestMetrics {
  model_name: string;
  accuracy: number;
  precision: number;
  recall: number;
  f1: number;
  roc_auc: number | null;
  average_precision: number | null;
  confusion_matrix: number[][];
  test_accuracy?: number;
  phishing_precision?: number;
  phishing_recall?: number;
  phishing_f1?: number;
  legitimate_precision?: number;
  legitimate_recall?: number;
  legitimate_f1?: number;
  macro_f1?: number;
  weighted_f1?: number;
}

export interface ValidationEntry {
  accuracy: number;
  precision?: number;
  recall?: number;
  f1?: number;
  phishing_precision?: number;
  phishing_recall?: number;
  phishing_f1?: number;
  macro_f1?: number;
  roc_auc: number | null;
  train_time_s?: number;
  fit_time_s?: number;
  cv_time_s?: number;
}

export interface FeatureImportance {
  feature: string;
  importance: number;
}

export interface ModelMetricsResponse {
  test_metrics: TestMetrics;
  validation_comparison?: Record<string, ValidationEntry>;
  cross_validation?: Record<string, any>;
  feature_importances?: FeatureImportance[];
  dataset_source?: string;
  dataset_size?: number;
  label_distribution?: Record<string, number>;
}

// ── Model Info ────────────────────────────────────────────────────────────

export interface ModelInfoResponse {
  model_available?: boolean;
  message?: string;
  model_name?: string;
  model_version?: string;
  feature_count?: number;
  feature_names?: string[];
  dataset_source?: string;
  dataset_size?: number;
  label_distribution?: Record<string, number>;
  trained_at?: string;
  class_mapping?: Record<string, string>;
}

// ── Generic API Error ─────────────────────────────────────────────────────

export interface ApiError {
  error: string;
}
