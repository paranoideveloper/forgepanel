import { plugin } from 'bun';
import { compile } from 'svelte/compiler';

plugin({
  name: 'svelte-loader',
  setup(build) {
    build.onLoad({ filter: /\.svelte$/ }, async (args) => {
      const text = await Bun.file(args.path).text();
      const compiled = compile(text, {
        filename: args.path,
        generate: 'client',
        dev: true
      });
      return {
        contents: compiled.js.code,
        loader: 'js'
      };
    });
  }
});
