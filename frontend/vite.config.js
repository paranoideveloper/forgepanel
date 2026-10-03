import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';
import { defineConfig } from 'vite';

// SvelteKit 3 reads its configuration from the plugin here; svelte.config.js
// is no longer supported.
export default defineConfig({
	plugins: [
		sveltekit({
			preprocess: vitePreprocess(),
			// SvelteKit 3 dropped the built-in $lib alias in favour of #lib; the
			// codebase imports $lib everywhere, which this keeps working.
			alias: { $lib: 'src/lib' },
			adapter: adapter({
				pages: '../internal/api/web',
				assets: '../internal/api/web',
				precompress: false,
				strict: true
			})
		})
	]
});
