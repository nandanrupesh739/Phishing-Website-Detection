/**
 * PhishGuard AI — Safe Value Formatters
 * Guarantees that null, undefined, or NaN never crash the UI or display "NaN%".
 */

export function formatPercent(
  value: number | null | undefined,
  decimals = 1
): string {
  if (value === null || value === undefined || typeof value !== 'number' || isNaN(value)) {
    return '—';
  }
  return `${(value * 100).toFixed(decimals)}%`;
}

export function formatNumber(
  value: number | null | undefined,
  decimals = 0
): string {
  if (value === null || value === undefined || typeof value !== 'number' || isNaN(value)) {
    return '—';
  }
  return decimals === 0
    ? Math.round(value).toLocaleString()
    : value.toLocaleString(undefined, {
        minimumFractionDigits: decimals,
        maximumFractionDigits: decimals,
      });
}

export function formatScore(
  value: number | null | undefined,
  decimals = 4
): string {
  if (value === null || value === undefined || typeof value !== 'number' || isNaN(value)) {
    return '—';
  }
  return value.toFixed(decimals);
}
