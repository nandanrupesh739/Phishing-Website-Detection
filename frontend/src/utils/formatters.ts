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

/**
 * Sanitize a CSV cell value to protect against CSV Formula Injection (CWE-1236).
 * Any cell starting with =, +, -, @ is prefixed with a single quote '.
 * Quotes within cells are escaped as "".
 */
export function sanitizeCsvCell(value: string | number | null | undefined): string {
  if (value === null || value === undefined) return '""';
  let str = String(value);
  // Formula injection protection: prefix with ' if starting with =, +, -, or @
  if (/^[=+\-@]/.test(str)) {
    str = `'${str}`;
  }
  return `"${str.replace(/"/g, '""')}"`;
}
