// Idle timeout.
//
// A panel session stays valid for as long as the refresh token lives, which
// means a dashboard left open on an unattended screen — a laptop in an office, a
// browser on a shared machine — hands whoever walks past it full control of
// every server. The refresh handling that made sessions survive expiry made this
// worse, not better: before, an idle tab eventually broke on its own.
//
// So: after a period with no sign of a human, sign out.
//
// A WARNING FIRST. Signing someone out mid-edit with no notice loses their work
// and teaches them to hate the panel. The warning fires a minute early, says how
// long is left, and any activity at all cancels it.
//
// WHAT COUNTS AS ACTIVITY is deliberately narrow: real input events, not timers
// or network traffic. Counting background polling would mean the panel keeps
// itself logged in forever, which is the same as having no timeout — the very
// bug this is written to avoid.

/** Events that indicate a person is actually there. */
const ACTIVITY_EVENTS = ['mousedown', 'keydown', 'touchstart', 'wheel', 'focus'] as const;

export interface IdleOptions {
  /** Total idle time before signing out. */
  timeoutMs?: number;
  /** How long before the deadline to warn. */
  warnMs?: number;
  /** Called once when the warning period begins, with seconds remaining. */
  onWarn?: (secondsLeft: number) => void;
  /** Called when the warning is cancelled by activity. */
  onResume?: () => void;
  /** Called when the deadline passes. */
  onTimeout: () => void;
}

/** Default: thirty minutes, warning at twenty-nine. */
export const DEFAULT_IDLE_MS = 30 * 60 * 1000;
export const DEFAULT_WARN_MS = 60 * 1000;

/**
 * watchIdle starts monitoring and returns a function that stops it.
 *
 * The returned stopper must be called on unmount: a timer that outlives the
 * component keeps firing against a dead callback, and listeners left on
 * `document` leak on every navigation.
 */
export function watchIdle(opts: IdleOptions): () => void {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_IDLE_MS;
  // A warning longer than the timeout would fire immediately and never stop
  // warning; clamp rather than trusting the caller's arithmetic.
  const warnMs = Math.min(opts.warnMs ?? DEFAULT_WARN_MS, Math.max(0, timeoutMs - 1));

  let warnTimer: ReturnType<typeof setTimeout> | undefined;
  let outTimer: ReturnType<typeof setTimeout> | undefined;
  let warning = false;
  let stopped = false;

  function clearTimers() {
    if (warnTimer !== undefined) clearTimeout(warnTimer);
    if (outTimer !== undefined) clearTimeout(outTimer);
    warnTimer = undefined;
    outTimer = undefined;
  }

  function arm() {
    if (stopped) return;
    clearTimers();
    if (warning) {
      warning = false;
      opts.onResume?.();
    }
    warnTimer = setTimeout(() => {
      warning = true;
      // Never report "0 seconds": a countdown that starts at zero reads as
      // already-expired, and the operator stops trusting the number.
      opts.onWarn?.(Math.max(1, Math.round(warnMs / 1000)));
    }, timeoutMs - warnMs);
    outTimer = setTimeout(() => {
      // Stop before calling out: the callback signs the session out, and a
      // rearm from a stray event afterwards would leave timers running against
      // a session that no longer exists.
      stop();
      opts.onTimeout();
    }, timeoutMs);
  }

  function onActivity() {
    arm();
  }

  // Returning to a tab is activity; leaving it is not. Without this, coming back
  // to a long-backgrounded tab shows the sign-out the instant you touch
  // anything, which reads as the panel breaking rather than protecting you.
  function onVisibility() {
    if (document.visibilityState === 'visible') arm();
  }

  function stop() {
    stopped = true;
    clearTimers();
    for (const ev of ACTIVITY_EVENTS) {
      document.removeEventListener(ev, onActivity, true);
    }
    document.removeEventListener('visibilitychange', onVisibility);
  }

  for (const ev of ACTIVITY_EVENTS) {
    // Capture phase: a handler that stops propagation deeper in the tree would
    // otherwise hide real activity and sign an active operator out.
    document.addEventListener(ev, onActivity, true);
  }
  document.addEventListener('visibilitychange', onVisibility);
  arm();

  return stop;
}
