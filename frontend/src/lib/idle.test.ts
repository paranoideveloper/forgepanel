import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { watchIdle, DEFAULT_IDLE_MS } from './idle';

describe('watchIdle', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('signs out after the timeout with no activity', () => {
    const onTimeout = vi.fn();
    const stop = watchIdle({ timeoutMs: 1000, warnMs: 200, onTimeout });

    vi.advanceTimersByTime(999);
    expect(onTimeout).not.toHaveBeenCalled();
    vi.advanceTimersByTime(2);
    expect(onTimeout).toHaveBeenCalledTimes(1);
    stop();
  });

  it('warns before signing out, not at the same moment', () => {
    const onWarn = vi.fn();
    const onTimeout = vi.fn();
    const stop = watchIdle({ timeoutMs: 10_000, warnMs: 2_000, onTimeout, onWarn });

    vi.advanceTimersByTime(8_000);
    // The warning has to arrive with time left to act on it. A warning fired
    // together with the sign-out is not a warning.
    expect(onWarn).toHaveBeenCalledTimes(1);
    // The countdown is reported in seconds, for a UI that says how long is left.
    expect(onWarn).toHaveBeenCalledWith(2);
    expect(onTimeout).not.toHaveBeenCalled();

    vi.advanceTimersByTime(2_000);
    expect(onTimeout).toHaveBeenCalledTimes(1);
    stop();
  });

  it('activity resets the clock', () => {
    const onTimeout = vi.fn();
    const stop = watchIdle({ timeoutMs: 1000, warnMs: 200, onTimeout });

    vi.advanceTimersByTime(900);
    document.dispatchEvent(new Event('keydown'));
    vi.advanceTimersByTime(900);
    // Without a reset this would have fired at 1000ms.
    expect(onTimeout).not.toHaveBeenCalled();
    vi.advanceTimersByTime(200);
    expect(onTimeout).toHaveBeenCalledTimes(1);
    stop();
  });

  it('activity during the warning cancels it', () => {
    const onWarn = vi.fn();
    const onResume = vi.fn();
    const stop = watchIdle({ timeoutMs: 1000, warnMs: 300, onTimeout: vi.fn(), onWarn, onResume });

    vi.advanceTimersByTime(750);
    expect(onWarn).toHaveBeenCalledTimes(1);
    document.dispatchEvent(new Event('mousedown'));
    // The UI must be told to take the banner down, or it sits there claiming an
    // imminent sign-out that is no longer coming.
    expect(onResume).toHaveBeenCalledTimes(1);

    vi.advanceTimersByTime(750);
    expect(onWarn).toHaveBeenCalledTimes(2);
    stop();
  });

  it('stops cleanly: no callback and no listeners after stop', () => {
    const onTimeout = vi.fn();
    const stop = watchIdle({ timeoutMs: 1000, warnMs: 200, onTimeout });
    stop();

    vi.advanceTimersByTime(5000);
    document.dispatchEvent(new Event('keydown'));
    vi.advanceTimersByTime(5000);
    // A timer outliving its component fires against a dead callback; a listener
    // left on document leaks on every navigation.
    expect(onTimeout).not.toHaveBeenCalled();
  });

  it('does not sign out twice', () => {
    const onTimeout = vi.fn();
    watchIdle({ timeoutMs: 100, warnMs: 20, onTimeout });
    vi.advanceTimersByTime(1000);
    // Activity after the deadline must not rearm a session that is already over.
    document.dispatchEvent(new Event('keydown'));
    vi.advanceTimersByTime(1000);
    expect(onTimeout).toHaveBeenCalledTimes(1);
  });

  it('clamps a warning longer than the timeout instead of warning forever', () => {
    const onWarn = vi.fn();
    const onTimeout = vi.fn();
    const stop = watchIdle({ timeoutMs: 100, warnMs: 5000, onTimeout, onWarn });
    vi.advanceTimersByTime(150);
    // ...and still reports a usable countdown rather than "0 seconds left".
    expect(onWarn).toHaveBeenCalledWith(1);
    // A warnMs above timeoutMs makes `timeoutMs - warnMs` negative, which fires
    // the warning immediately and, once rearmed, in a tight loop.
    expect(onWarn).toHaveBeenCalledTimes(1);
    expect(onTimeout).toHaveBeenCalledTimes(1);
    stop();
  });

  it('defaults to a timeout long enough to be usable', () => {
    // A ten-second idle timeout is a denial of service against the operator.
    // Thirty minutes is the shape of the thing; the exact value can move.
    expect(DEFAULT_IDLE_MS).toBeGreaterThanOrEqual(10 * 60 * 1000);
  });
});
