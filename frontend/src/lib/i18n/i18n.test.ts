import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { en } from './en';
import { fa } from './fa';
import { tr, detectLocale, catalogs, applyDocumentLocale, locales } from './state.svelte';

const SRC = join(import.meta.dirname, '..', '..');

function walk(dir: string, out: string[] = []): string[] {
	for (const name of readdirSync(dir)) {
		const p = join(dir, name);
		if (statSync(p).isDirectory()) walk(p, out);
		else if (p.endsWith('.svelte')) out.push(p);
	}
	return out;
}
const components = walk(SRC);

/** Strip <script> and <style>, leaving the template. */
function template(src: string): string {
	return src.replace(/<script[\s\S]*?<\/script>/g, '').replace(/<style[\s\S]*?<\/style>/g, '');
}

/** Strip comments — a tr('...') inside one documents the API, it does not call it. */
function decomment(src: string): string {
	return src
		.replace(/<!--[\s\S]*?-->/g, '')
		.replace(/\/\*[\s\S]*?\*\//g, '')
		.replace(/(^|[^:'"\\])\/\/[^\n]*/g, '$1');
}

/** Every tr('key') / tr("key") literal referenced anywhere in the components. */
function usedKeys(): Map<string, string[]> {
	const used = new Map<string, string[]>();
	for (const f of components) {
		const src = decomment(readFileSync(f, 'utf8'));
		for (const m of src.matchAll(/\btr\(\s*['"]([^'"]+)['"]/g)) {
			const list = used.get(m[1]) ?? [];
			list.push(relative(SRC, f));
			used.set(m[1], list);
		}
	}
	return used;
}

describe('catalogs', () => {
	it('cover exactly the same keys in every language', () => {
		// A key present in one catalog and missing from another is a string that
		// silently falls back to English for some users. It renders, so nothing
		// looks broken — the panel is just half-translated for the people who
		// needed the translation.
		const enKeys = new Set(Object.keys(en));
		const faKeys = new Set(Object.keys(fa));
		const missingInFa = [...enKeys].filter((k) => !faKeys.has(k));
		const extraInFa = [...faKeys].filter((k) => !enKeys.has(k));
		expect({ missingInFa, extraInFa }).toEqual({ missingInFa: [], extraInFa: [] });
	});

	it('keep the same interpolation placeholders in every language', () => {
		// The failure this catches: a translator writes the sentence but drops
		// {ttl}, so "online for {ttl} seconds" becomes "online for seconds" — a
		// missing NUMBER, in a language nobody reviewing the diff reads. Nothing
		// throws and no test that only checks wording would notice.
		const placeholders = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();
		const drift: Record<string, { en: string[]; fa: string[] }> = {};
		for (const key of Object.keys(en)) {
			if (!(key in fa)) continue;
			const a = placeholders(en[key]);
			const b = placeholders(fa[key]);
			if (a.join(',') !== b.join(',')) drift[key] = { en: a, fa: b };
		}
		expect(drift).toEqual({});
	});

	it('have no key that nothing renders', () => {
		// Dead keys are translation work spent on strings nobody sees, and they
		// make the catalog look more complete than the panel is.
		const used = usedKeys();
		const dynamic = new Set<string>();
		// Keys referenced indirectly (labelKey/descKey held in data) are used by
		// tr(x) with a variable, so the literal scan cannot see them.
		for (const f of components) {
			const src = readFileSync(f, 'utf8');
			for (const m of src.matchAll(/(?:labelKey|descKey)\s*:\s*['"]([^'"]+)['"]/g))
				dynamic.add(m[1]);
		}
		const orphans = Object.keys(en).filter((k) => !used.has(k) && !dynamic.has(k));
		expect(orphans).toEqual([]);
	});

	it('define every key the components ask for', () => {
		// tr() on an unknown key renders the key itself. "users.delete_confirm"
		// on a button looks like a bug to whoever is using the panel.
		const unknown = [...usedKeys().entries()]
			.filter(([k]) => !(k in en))
			.map(([k, files]) => `${k} (${files.join(', ')})`);
		expect(unknown).toEqual([]);
	});
});

describe('tr', () => {
	it('interpolates named params', () => {
		expect(tr('__test__', {})).toBe('__test__'); // unknown key renders the key
		catalogs.en['__test__'] = 'online for {ttl} seconds';
		expect(tr('__test__', { ttl: 300 })).toBe('online for 300 seconds');
		delete catalogs.en['__test__'];
	});

	it('leaves a placeholder alone when the param was never passed', () => {
		// The distinction that matters: never-passed is a mistake and stays
		// visible; passed-but-undefined is an optional field and renders empty,
		// which is what Svelte's own {expr} does. Printing the word "undefined"
		// for either would hide both.
		catalogs.en['__t2__'] = 'Delete {name}?';
		expect(tr('__t2__')).toBe('Delete {name}?');
		expect(tr('__t2__', {})).toBe('Delete {name}?');
		expect(tr('__t2__', { name: undefined })).toBe('Delete ?');
		expect(tr('__t2__', { name: 'sam' })).toBe('Delete sam?');
		delete catalogs.en['__t2__'];
	});
});

describe('detectLocale', () => {
	it('prefers a remembered choice over the browser', () => {
		expect(detectLocale('fa', ['en-US'])).toBe('fa');
		expect(detectLocale('en', ['fa-IR'])).toBe('en');
	});

	it('falls back to the browser preference, matching the primary subtag', () => {
		// 'fa-IR' and 'fa_IR' both mean Persian. Comparing the whole tag would
		// send an Iranian operator to English on first load, which is the exact
		// person this locale exists for.
		expect(detectLocale(null, ['fa-IR', 'en'])).toBe('fa');
		expect(detectLocale(null, ['fa_IR'])).toBe('fa');
		expect(detectLocale(null, ['FA'])).toBe('fa');
	});

	it('ignores a stored value that is not a locale', () => {
		expect(detectLocale('klingon', [])).toBe('en');
		expect(detectLocale(null, ['de-DE'])).toBe('en');
	});
});

/**
 * Names that are the same in every language: product names, protocols, wire
 * identifiers, units. Translating "VLESS" or "Xray" would stop matching the
 * config the panel writes and the upstream docs an operator is reading.
 */
const NOT_TRANSLATED = new Set([
	'ForgePanel', 'ForgeDNS', 'ForgeEdge', 'ForgeNode', 'Xray', 'sing-box', 'Cloudflare',
	'VLESS', 'VMess', 'Trojan', 'Shadowsocks', 'SOCKS5', 'HTTP', 'HTTPS', 'TLS', 'mTLS',
	'TCP', 'UDP', 'WireGuard', 'AmneziaWG', 'Hysteria2', 'TUIC', 'AnyTLS', 'ShadowTLS',
	'Reality', 'REALITY', 'XHTTP', 'gRPC', 'WebSocket', 'mKCP', 'Snell', 'Juicity', 'Mieru',
	'Brook', 'SSH', 'DNS', 'DoH', 'DoT', 'ACME', 'JSON', 'YAML', 'QR', 'URI', 'URL', 'IP',
	'IPv4', 'IPv6', 'CIDR', 'SNI', 'ALPN', 'UUID', 'API', 'CPU', 'RAM', 'GB', 'MB', 'KB',
	'TB', 'ms', 'OK', 'ID', 'UI', 'CDN', 'NAT', 'CA', 'JWT', 'TOTP', '2FA', 'SSL', 'Clash',
	'v2ray', 'geoip', 'geosite', 'systemd',
	// Wire values and key names, not prose: they are compared or sent verbatim,
	// and translating one would break the comparison rather than the wording.
	'Escape', 'Enter', 'Tab', 'none', 'tls', 'reality', 'grpc', 'ws', 'tcp', 'xhttp',
	'h2,http/1.1', 'http/1.1', 'success', 'error', 'info', 'warning'
]);

/** Text runs between tags, with {moustaches} and block tags removed. */
function proseRuns(tmpl: string): string[] {
	const runs: string[] = [];
	// Drop comments and every {…} — a moustache is code, not copy.
	let t = tmpl.replace(/<!--[\s\S]*?-->/g, '');
	let depth = 0;
	let stripped = '';
	for (const ch of t) {
		if (ch === '{') depth++;
		else if (ch === '}') depth = Math.max(0, depth - 1);
		else if (depth === 0) stripped += ch;
	}
	for (const chunk of stripped.split(/<[^>]*>/)) {
		const s = chunk.replace(/\s+/g, ' ').trim();
		if (s) runs.push(s);
	}
	return runs;
}

describe('no hard-coded user-facing text', () => {
	it('leaves no prose in a component template', () => {
		// The point of this guard is the NEXT string, not the ones already moved.
		// Every view still to be built would otherwise land a fresh crop of
		// English literals, and someone would have to find them all again — which
		// is exactly the cost that made doing i18n early worth it.
		const offenders: string[] = [];
		for (const f of components) {
			const src = decomment(readFileSync(f, 'utf8'));
			for (const run of proseRuns(template(src))) {
				if (NOT_TRANSLATED.has(run)) continue;
				// Needs two consecutive letters to be a word rather than a symbol,
				// an arrow, a unit or a bare number.
				if (!/[A-Za-z]{2}/.test(run)) continue;
				offenders.push(`${relative(SRC, f)}: ${JSON.stringify(run)}`);
			}
		}
		expect(offenders).toEqual([]);
	});

	it('leaves no prose in a user-visible attribute', () => {
		// placeholder and title are the two that get missed most: they are not
		// visible in the rendered text a reviewer skims, only when someone focuses
		// the field or hovers.
		const offenders: string[] = [];
		for (const f of components) {
			const src = decomment(readFileSync(f, 'utf8'));
			const tmpl = template(src);
			for (const attr of ['placeholder', 'title', 'aria-label', 'alt']) {
				const re = new RegExp(`\\b${attr}="([^"{}]*)"`, 'g');
				for (const m of tmpl.matchAll(re)) {
					const v = m[1].trim();
					if (!v || NOT_TRANSLATED.has(v) || !/[A-Za-z]{2}/.test(v)) continue;
					offenders.push(`${relative(SRC, f)}: ${attr}=${JSON.stringify(v)}`);
				}
			}
		}
		expect(offenders).toEqual([]);
	});

	it('leaves no prose inside a moustache expression', () => {
		// The gap the first version of this guard had: it stripped every {…}
		// before looking, so `{r.enabled ? 'Disable' : 'Enable'}` — a ternary
		// rendering two English words straight into a button — sailed through.
		// Conditional labels are exactly where untranslated strings hide, because
		// only one branch is visible at a time.
		const offenders: string[] = [];
		for (const f of components) {
			const src = decomment(readFileSync(f, 'utf8'));
			for (const m of template(src).matchAll(/\{([^{}]*)\}/g)) {
				// Remove tr() calls first. Their argument is a KEY, and leaving
				// them in also makes the literal scanner below run onto the next
				// quote and report nonsense like "? tr(".
				const expr = m[1].replace(/\btr\(\s*(['"])[^'"]*\1/g, 'tr(');
				// Only quoted literals; an attribute value or a class name is not
				// prose, and neither is a lone identifier.
				for (const lit of expr.matchAll(/'([^'\\]{2,})'|"([^"\\]{2,})"/g)) {
					const v = (lit[1] ?? lit[2]).trim();
					if (!/[A-Za-z]{2}/.test(v)) continue;
					if (NOT_TRANSLATED.has(v)) continue;
					// A key passed to tr() is not prose, and neither is anything
					// that looks like an identifier, path, class or MIME type.
					if (/^[a-z0-9_.\-/:]+$/.test(v)) continue;
					offenders.push(`${relative(SRC, f)}: ${JSON.stringify(v)}`);
				}
			}
		}
		expect(offenders).toEqual([]);
	});
});

describe('text direction', () => {
	it('puts the locale and its direction on <html>', () => {
		// This is the half that a translation catalogue alone does not solve. The
		// stylesheets were converted to logical properties (margin-inline-start,
		// text-align: start, inset-inline-end), and every one of them is inert
		// until dir is actually set on the root element — so a missing dir gives
		// Persian words in a layout still flowing left-to-right.
		applyDocumentLocale('fa');
		expect(document.documentElement.dir).toBe('rtl');
		expect(document.documentElement.lang).toBe('fa');

		applyDocumentLocale('en');
		expect(document.documentElement.dir).toBe('ltr');
		expect(document.documentElement.lang).toBe('en');
	});

	it('reports the direction for each locale it offers', () => {
		expect(locales.map((l) => [l.code, l.dir])).toEqual([
			['en', 'ltr'],
			['fa', 'rtl']
		]);
	});

	it('names each language in that language', () => {
		// An English label in a language picker is no help to someone who cannot
		// read English — which is the only person who needs the picker.
		expect(locales.find((l) => l.code === 'fa')?.nativeName).toBe('فارسی');
	});
});
