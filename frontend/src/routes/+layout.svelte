<script lang="ts">
	import favicon from '$lib/assets/favicon.svg';
	import { locale, applyDocumentLocale } from '$lib/i18n';

	let { children } = $props();

	// Mirror the detected locale onto <html> as soon as the app mounts, not only
	// when someone uses the switcher. Without this a returning Persian-speaking
	// operator gets Persian words in a left-to-right layout: the text is
	// translated and the page is still laid out backwards, which is harder to
	// read than English would have been.
	$effect(() => {
		applyDocumentLocale(locale());
	});
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
</svelte:head>

{@render children()}
