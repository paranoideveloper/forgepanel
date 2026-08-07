/**
 * Worker bindings.
 *
 * KV is the only REQUIRED binding. D1 is optional and, when present, mirrors the
 * config plus a small audit trail — nothing in the data path depends on it, so a
 * deployment without D1 behaves identically.
 *
 * The `vars` below are all optional escape hatches for people who prefer to pin
 * something in wrangler.jsonc. Leaving every one of them unset is the supported
 * default: ForgeEdge bootstraps itself into KV on first request.
 */

export interface Env {
  KV: KVNamespace;
  DB?: D1Database;

  /** Optional: pin the secure path instead of letting the Worker mint one. */
  SECURE_PATH?: string;
  /** Optional: seed the admin password on first boot (hashed immediately, never stored raw). */
  ADMIN_PASSWORD?: string;
  /** Optional: pre-shared token the ForgePanel VPS uses to push its canonical feed. */
  FEED_PUSH_TOKEN?: string;
  /** Optional: Cloudflare API token, only for the panel's self-update/delete actions. */
  CF_API_TOKEN?: string;
  /** Optional: account id that pairs with CF_API_TOKEN. */
  CF_ACCOUNT_ID?: string;
  /** Set to "1" by Cloudflare Pages; selects the Pages deploy path in the panel. */
  CF_PAGES?: string;
}
