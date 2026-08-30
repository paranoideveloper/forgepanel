/**
 * Theme selection.
 *
 * The panel was dark-only, not by choice but because every colour in it was a
 * literal: 309 hex values and 222 rgba(255,255,255,a) restated across 29 files.
 * The alpha-white ones are why a light theme could not simply be "swap the
 * background" — muted text written as rgba(255,255,255,.55) is invisible on
 * paper by construction. Those are now tokens (see src/app.html), and this
 * picks which set of them is live.
 *
 * 'system' is the default and is a real third state, not a synonym for dark: it
 * follows the operator's OS setting and keeps following it when that changes.
 */

export type Theme = 'system' | 'dark' | 'light';

const KEY = 'forgepanel.theme';

let current = $state<Theme>('system');

export function theme(): Theme {
	return current;
}

/** The theme actually being painted, with 'system' resolved. */
export function resolvedTheme(): 'dark' | 'light' {
	if (current !== 'system') return current;
	if (typeof window === 'undefined' || !window.matchMedia) return 'dark';
	return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

export function setTheme(next: Theme) {
	current = next;
	// Wrapped: a private window, or a browser told to block site data, throws on
	// access. A theme preference must never be the reason the panel fails to
	// start.
	try {
		localStorage.setItem(KEY, next);
	} catch {
		/* preference is not persisted; the session still themes correctly */
	}
	applyDocumentTheme(next);
}

/**
 * Stamp the choice onto <html>.
 *
 * 'system' stamps NOTHING, so the :root defaults and the prefers-color-scheme
 * override in app.html decide. Stamping data-theme="dark" for system would
 * freeze it at whatever the OS said the first time.
 */
export function applyDocumentTheme(next: Theme = current) {
	if (typeof document === 'undefined') return;
	const el = document.documentElement;
	if (next === 'system') el.removeAttribute('data-theme');
	else el.setAttribute('data-theme', next);
}

/** Read the stored preference. Called once, as the app mounts. */
export function initTheme() {
	let stored: string | null = null;
	try {
		stored = localStorage.getItem(KEY);
	} catch {
		/* nothing stored is readable; fall through to system */
	}
	current = stored === 'dark' || stored === 'light' || stored === 'system' ? stored : 'system';
	applyDocumentTheme(current);
}
