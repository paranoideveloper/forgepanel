import { describe, it, expect, afterEach } from 'vitest';
import {
  DEFAULT_PRESENCE_TTL_SECONDS,
  isPresent,
  presenceTtlSeconds,
  presenceWindowMs,
  setPresenceTtlSeconds
} from './presence';

// The window is module state on purpose — every screen has to see the same one
// — so each test puts it back afterwards rather than leaking a window into the
// next test.
afterEach(() => setPresenceTtlSeconds(DEFAULT_PRESENCE_TTL_SECONDS));

describe('presence window', () => {
  it('defaults to the backend tracker TTL, not a longer guess', () => {
    // internal/core/online/tracker.go DefaultTTL is two minutes. A frontend
    // default of three (which the Users table used to carry) marks a user
    // online for a full minute after the backend has already dropped them.
    expect(DEFAULT_PRESENCE_TTL_SECONDS).toBe(120);
    expect(presenceTtlSeconds()).toBe(120);
    expect(presenceWindowMs()).toBe(120_000);
  });

  it('counts a user online inside the window and offline outside it', () => {
    const now = Date.parse('2026-08-28T12:00:00Z');
    const at = (secondsAgo: number) => new Date(now - secondsAgo * 1000).toISOString();

    expect(isPresent(at(0), now)).toBe(true);
    expect(isPresent(at(119), now)).toBe(true);
    // 2m30s: green dot in Users, absent from Online. That disagreement is the
    // whole reason this module exists.
    expect(isPresent(at(150), now)).toBe(false);
    expect(isPresent(at(3600), now)).toBe(false);
  });

  it('follows the window the server published', () => {
    const now = Date.parse('2026-08-28T12:00:00Z');
    const at = (secondsAgo: number) => new Date(now - secondsAgo * 1000).toISOString();

    expect(isPresent(at(150), now)).toBe(false);
    expect(setPresenceTtlSeconds(300)).toBe(300);
    expect(isPresent(at(150), now)).toBe(true);
    expect(presenceWindowMs()).toBe(300_000);
  });

  it('keeps the current window when the server value is missing or nonsense', () => {
    setPresenceTtlSeconds(300);
    // A response that came back without the field must not collapse the window
    // to zero and mark everyone offline, which reads as an outage.
    expect(setPresenceTtlSeconds(undefined)).toBe(300);
    expect(setPresenceTtlSeconds(0)).toBe(300);
    expect(setPresenceTtlSeconds(-5)).toBe(300);
    expect(setPresenceTtlSeconds('nonsense')).toBe(300);
    expect(presenceTtlSeconds()).toBe(300);
  });

  it('treats a missing or unparseable timestamp as never seen', () => {
    expect(isPresent(undefined)).toBe(false);
    expect(isPresent(null)).toBe(false);
    expect(isPresent('')).toBe(false);
    expect(isPresent('not a date')).toBe(false);
  });
});
