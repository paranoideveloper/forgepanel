/**
 * Per-request runtime state.
 *
 * A Worker isolate handles many requests, so this is set at the top of every
 * `fetch()` and read by the handlers below it. It exists so the hot data path
 * (vless.ts / trojan.ts) can consult the log level without threading the whole
 * config through half a dozen call frames.
 */

import type { EdgeConfig, EdgeSecrets } from './schema';

let currentConfig: EdgeConfig | null = null;
let currentSecrets: EdgeSecrets | null = null;

export function setRuntime(config: EdgeConfig, secrets: EdgeSecrets): void {
  currentConfig = config;
  currentSecrets = secrets;
}

export function getGlobalConfig(): EdgeConfig | null { return currentConfig; }
export function getGlobalSecrets(): EdgeSecrets | null { return currentSecrets; }

/** Test seam: reset between cases so state never leaks across assertions. */
export function clearRuntime(): void {
  currentConfig = null;
  currentSecrets = null;
}
