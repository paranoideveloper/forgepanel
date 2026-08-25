// Locale, translation lookup, and text direction.
//
// This exists early rather than late on purpose. Every hard-coded English
// string written before an i18n layer exists has to be found and moved
// afterwards, and the ones that get missed are the ones nobody reads in
// review — a placeholder, a title attribute, a toast that only fires on an
// error path. Doing it after the remaining views were built would have meant
// paying for each of those strings twice.
//
// Persian is the second locale because it is the audience that most needs the
// panel and it is RIGHT-TO-LEFT, which is the part a translation layer alone
// does not solve. A panel that swaps its words but keeps its layout mirrored
// the wrong way is harder to use than one left in English.

import { en } from './en';
import { fa } from './fa';

export type Locale = 'en' | 'fa';

export interface LocaleMeta {
	code: Locale;
	/** The language's name IN that language — an English label in a language
	 * picker is no use to someone who cannot read English. */
	nativeName: string;
	dir: 'ltr' | 'rtl';
}

export const locales: LocaleMeta[] = [
	{ code: 'en', nativeName: 'English', dir: 'ltr' },
	{ code: 'fa', nativeName: 'فارسی', dir: 'rtl' }
];

export const catalogs: Record<Locale, Record<string, string>> = { en, fa };

const STORAGE_KEY = 'forgepanel.locale';

function isLocale(v: unknown): v is Locale {
	return v === 'en' || v === 'fa';
}

/**
 * Reads a remembered choice, then the browser's own preference.
 *
 * navigator.language is consulted before defaulting to English so that a
 * Persian-speaking operator opening the panel for the first time does not have
 * to find a language menu written in a language they may not read.
 */
export function detectLocale(
	stored: string | null,
	navigatorLanguages: readonly string[] = []
): Locale {
	if (isLocale(stored)) return stored;
	for (const lang of navigatorLanguages) {
		// 'fa', 'fa-IR', 'fa_IR' — match the primary subtag only.
		const primary = lang.toLowerCase().split(/[-_]/)[0];
		if (isLocale(primary)) return primary;
	}
	return 'en';
}

function readStored(): string | null {
	try {
		return localStorage.getItem(STORAGE_KEY);
	} catch {
		// Private browsing and blocked site-data both throw here. A panel that
		// cannot remember a language preference must still render in one.
		return null;
	}
}

let current = $state<Locale>(
	typeof window === 'undefined'
		? 'en'
		: detectLocale(readStored(), navigator.languages ?? [navigator.language])
);

export function locale(): Locale {
	return current;
}

export function dir(): 'ltr' | 'rtl' {
	return locales.find((l) => l.code === current)?.dir ?? 'ltr';
}

export function setLocale(next: Locale) {
	current = next;
	try {
		localStorage.setItem(STORAGE_KEY, next);
	} catch {
		// Not remembering the choice is survivable; failing to apply it is not.
	}
	applyDocumentLocale(next);
}

/**
 * Mirrors the locale onto <html lang> and <html dir>.
 *
 * dir on the root element is what actually flips the layout: it reverses flex
 * and grid flow, swaps the meaning of the logical margin/padding properties the
 * stylesheets use, and moves scrollbars. Setting lang as well is not cosmetic —
 * it selects the right font stack and tells a screen reader which language to
 * pronounce.
 */
export function applyDocumentLocale(next: Locale) {
	if (typeof document === 'undefined') return;
	const meta = locales.find((l) => l.code === next);
	document.documentElement.lang = next;
	document.documentElement.dir = meta?.dir ?? 'ltr';
}

/**
 * Looks up a key in the active catalog.
 *
 * Missing keys fall back to English rather than rendering the raw key. A half
 * translated panel showing "users.quota.exceeded" where a sentence belongs is
 * worse than one showing an English sentence: the English is at least readable,
 * and a raw key looks like a bug to the person using it.
 *
 * Named `tr` rather than the conventional `t` deliberately. `t` is an ordinary
 * local-variable name — this codebase already had seven of them, mostly
 * `{#each ticks as t}` — and a loop variable shadowing the import turns
 * `{t('key')}` into calling the loop item as a function. That fails at runtime,
 * only on the path that renders, and only once someone adds a translated string
 * inside a loop that already existed. Renaming the import once removes the
 * hazard; the alternative is a rule every future contributor has to remember.
 *
 * `params` interpolates {name} placeholders. A placeholder with no matching
 * param is left as-is: emitting an empty string would silently produce
 * "Delete ?" and hide the mistake. A param that IS supplied but holds
 * undefined renders empty, matching what Svelte does with {maybeUndefined}.
 */
export function tr(
	key: string,
	params?: Record<string, string | number | undefined | null>
): string {
	const template = catalogs[current][key] ?? catalogs.en[key];
	if (template === undefined) return key;
	if (!params) return template;
	return template.replace(/\{(\w+)\}/g, (whole, name: string) => {
		if (!(name in params)) return whole;
		const v = params[name];
		// A param that was PASSED and is undefined renders empty, which is what
		// Svelte's own {expr} does for an optional field. A param that was never
		// passed keeps its {placeholder} — that one is a mistake and should be
		// visible. String(undefined) would print the word "undefined" into the UI
		// for both cases and hide the difference.
		return v === undefined || v === null ? '' : String(v);
	});
}

/**
 * Formats a number in the active locale's own digits.
 *
 * Persian uses Eastern Arabic numerals, and a table of traffic figures in Latin
 * digits inside an otherwise Persian right-to-left page reads as unfinished.
 */
export function num(value: number, options?: Intl.NumberFormatOptions): string {
	const tag = current === 'fa' ? 'fa-IR' : 'en-US';
	try {
		return new Intl.NumberFormat(tag, options).format(value);
	} catch {
		return String(value);
	}
}
