import { describe, it, expect, vi } from 'vitest';
import { render } from '@testing-library/svelte';
import Toast, { showToast, toasts, type ToastMessage } from './Toast.svelte';

describe('Toast Component', () => {
  it('adds and auto-dismisses success, error, and info toast messages', async () => {
    vi.useFakeTimers();
    render(Toast);

    showToast('Success msg', 'success');
    showToast('Error msg', 'error');
    showToast('Info msg', 'info');

    let currentToasts: ToastMessage[] = [];
    toasts.subscribe(val => { currentToasts = val; })();
    expect(currentToasts).toHaveLength(3);
    expect(currentToasts[0].text).toBe('Success msg');
    expect(currentToasts[1].text).toBe('Error msg');
    expect(currentToasts[2].text).toBe('Info msg');

    vi.advanceTimersByTime(4500);
    toasts.subscribe(val => { currentToasts = val; })();
    expect(currentToasts).toHaveLength(0);

    vi.useRealTimers();
  });
});
