// Re-export so components can `import { tr } from '$lib/i18n'`.
//
// The implementation lives in state.svelte.ts because it holds $state, and
// Svelte 5 only compiles runes in files named *.svelte.ts. That extension does
// not participate in directory-index resolution, so this plain index is what
// makes the short import path work.
export {
	tr,
	num,
	locale,
	setLocale,
	dir,
	locales,
	catalogs,
	detectLocale,
	applyDocumentLocale
} from './state.svelte';
export type { Locale, LocaleMeta } from './state.svelte';
