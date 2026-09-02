// `cloudflare:sockets` is a workerd built-in, externalized in the real bundle
// and provided by the runtime. It is not resolvable under `bun test`, so any
// test that transitively imports the data-path modules needs a stub. The stub's
// connect() throws — no test exercises a real outbound socket.
import { plugin } from 'bun';

plugin({
  name: 'cloudflare-sockets-stub',
  setup(build) {
    build.module('cloudflare:sockets', () => ({
      loader: 'object',
      exports: {
        connect() {
          throw new Error('cloudflare:sockets is not available under bun test');
        },
      },
    }));
  },
});
