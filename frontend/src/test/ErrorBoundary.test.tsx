import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { ErrorBoundary } from '../components/ErrorBoundary';

function BuggyComponent({ shouldThrow }: { shouldThrow: boolean }) {
  if (shouldThrow) {
    throw new Error('Test crash in page component');
  }
  return <div>Component loaded normally</div>;
}

describe('ErrorBoundary Component', () => {
  it('renders children normally when there is no error', () => {
    render(
      <ErrorBoundary pageName="Test Page">
        <BuggyComponent shouldThrow={false} />
      </ErrorBoundary>
    );

    expect(screen.getByText('Component loaded normally')).toBeInTheDocument();
  });

  it('catches render errors and displays fallback UI without blanking the app', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});

    render(
      <ErrorBoundary pageName="Scanner Page">
        <BuggyComponent shouldThrow={true} />
      </ErrorBoundary>
    );

    expect(screen.getByText(/Scanner Page encountered an error/i)).toBeInTheDocument();
    expect(screen.getByText(/Test crash in page component/i)).toBeInTheDocument();
    expect(screen.getByText(/Try Again/i)).toBeInTheDocument();

    spy.mockRestore();
  });

  it('allows user to retry after an error is caught', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});

    const { rerender } = render(
      <ErrorBoundary pageName="Dashboard">
        <BuggyComponent shouldThrow={true} />
      </ErrorBoundary>
    );

    expect(screen.getByText(/Dashboard encountered an error/i)).toBeInTheDocument();

    // Rerender with healthy state and click Try Again
    rerender(
      <ErrorBoundary pageName="Dashboard">
        <BuggyComponent shouldThrow={false} />
      </ErrorBoundary>
    );

    const retryBtn = screen.getByText(/Try Again/i);
    fireEvent.click(retryBtn);

    expect(screen.getByText('Component loaded normally')).toBeInTheDocument();

    spy.mockRestore();
  });
});
