/**
 * Config + secret persistence.
 *
 * KV holds everything. D1, when bound, receives a mirror of each write plus an
 * audit row — useful for "who changed what" and for a rollback, but never on the
 * read path, so a missing/broken D1 cannot take the Worker down.
 *
 * The COMPULSORY secure path is minted here on first boot. There is no mode in
 * which ForgeEdge serves a panel or a subscription from an unguessable-free URL:
 * `loadSecrets` cannot return a record without one.
 */

import type { Env } from '../env';
import {
  type EdgeConfig, type EdgeSecrets, KV_KEYS, CONFIG_VERSION, defaultConfig,
} from './schema';
import { b64RawURL } from '../common/encoding';
import { sha256Hex } from '../common/sha';

/** URL-safe random token of `bytes` entropy. 16 bytes ⇒ 22 chars. */
export function randomToken(bytes = 16): string {
  const b = new Uint8Array(bytes);
  crypto.getRandomValues(b);
  return b64RawURL(b);
}

/**
 * The secure path. Lowercased alphanumerics only: it is typed by hand on phones,
 * pasted into clients that mangle case, and logged by intermediaries.
 */
export function randomSecurePath(len = 24): string {
  // 32 symbols: a-z minus l and o, digits 2-9. The ambiguous glyphs (l/1, o/0)
  // are gone because this string gets read off a screen and retyped on a phone.
  // 32 is a power of two, so `% length` over random bytes stays unbiased.
  const alphabet = 'abcdefghijkmnpqrstuvwxyz23456789';
  const b = new Uint8Array(len);
  crypto.getRandomValues(b);
  let out = '';
  for (let i = 0; i < len; i++) out += alphabet[b[i] % alphabet.length];
  return out;
}

export function hashPassword(salt: string, password: string): string {
  return sha256Hex(`forgeedge:${salt}:${password}`);
}

function newSecrets(env: Env): EdgeSecrets {
  const now = new Date().toISOString();
  const salt = randomToken(12);
  return {
    securePath: env.SECURE_PATH && /^[a-z0-9-]{8,64}$/.test(env.SECURE_PATH)
      ? env.SECURE_PATH
      : randomSecurePath(),
    sessionKey: randomToken(32),
    feedPushToken: env.FEED_PUSH_TOKEN || randomToken(24),
    adminSalt: salt,
    adminHash: env.ADMIN_PASSWORD ? hashPassword(salt, env.ADMIN_PASSWORD) : '',
    createdAt: now,
    rotatedAt: now,
  };
}

async function kvGetJSON<T>(env: Env, key: string): Promise<T | null> {
  try {
    return await env.KV.get<T>(key, { type: 'json' });
  } catch {
    return null;
  }
}

export async function loadSecrets(env: Env): Promise<EdgeSecrets> {
  const found = await kvGetJSON<EdgeSecrets>(env, KV_KEYS.secrets);
  if (found && found.securePath && found.sessionKey) return found;
  const fresh = newSecrets(env);
  await env.KV.put(KV_KEYS.secrets, JSON.stringify(fresh));
  // The operator has no other way to learn the path on a fresh deploy.
  console.log(`[forgeedge] bootstrapped. Panel: /${fresh.securePath}/panel`);
  return fresh;
}

export async function saveSecrets(env: Env, s: EdgeSecrets): Promise<void> {
  await env.KV.put(KV_KEYS.secrets, JSON.stringify(s));
}

/** Regenerate the secure path (and optionally the session key), invalidating every old URL. */
export async function rotateSecurePath(env: Env, alsoSessions = true): Promise<EdgeSecrets> {
  const s = await loadSecrets(env);
  s.securePath = randomSecurePath();
  if (alsoSessions) s.sessionKey = randomToken(32);
  s.rotatedAt = new Date().toISOString();
  await saveSecrets(env, s);
  return s;
}

/**
 * Fill in anything a stored config predates, so an upgrade never leaves a field
 * `undefined` in the middle of a renderer.
 */
export function migrateConfig(stored: Partial<EdgeConfig> | null): EdgeConfig {
  const base = defaultConfig();
  if (!stored) return base;
  const merged: EdgeConfig = {
    ...base,
    ...stored,
    routing: { ...base.routing, ...(stored.routing ?? {}) },
    warp: { ...base.warp, ...(stored.warp ?? {}) },
    fragment: { ...base.fragment, ...(stored.fragment ?? {}) },
    backend: { ...base.backend, ...(stored.backend ?? {}) },
    // Not for the missing-key case — the spread above already covers that. This
    // is for a PARTIAL object: the panel writes whole top-level keys verbatim
    // (internal/api/edge_config.go) from a JSON textarea, so `{"enabled":false}`
    // would otherwise leave every bound `undefined` in the hot path.
    limits: { ...base.limits, ...(stored.limits ?? {}) },
    version: CONFIG_VERSION,
  };
  return merged;
}

export async function loadConfig(env: Env): Promise<EdgeConfig> {
  const stored = await kvGetJSON<Partial<EdgeConfig>>(env, KV_KEYS.config);
  const cfg = migrateConfig(stored);

  // Mint the client-facing identity on first boot so a fresh deploy already has
  // a working subscription without the operator touching anything.
  let dirty = !stored || stored.version !== CONFIG_VERSION;
  if (!cfg.vlessUUID) { cfg.vlessUUID = crypto.randomUUID(); dirty = true; }
  if (!cfg.trojanPassword) { cfg.trojanPassword = randomToken(18); dirty = true; }
  if (!cfg.wsPathSalt) { cfg.wsPathSalt = randomToken(12); dirty = true; }

  if (dirty) await saveConfig(env, cfg);
  return cfg;
}

export async function saveConfig(env: Env, cfg: EdgeConfig, actor = 'system'): Promise<void> {
  cfg.version = CONFIG_VERSION;
  await env.KV.put(KV_KEYS.config, JSON.stringify(cfg));
  await mirrorToD1(env, cfg, actor);
}

/** Optional D1 mirror + audit row. Failures are logged, never propagated. */
async function mirrorToD1(env: Env, cfg: EdgeConfig, actor: string): Promise<void> {
  if (!env.DB) return;
  try {
    await env.DB.exec(
      'CREATE TABLE IF NOT EXISTS forgeedge_config (id INTEGER PRIMARY KEY, updated_at TEXT, actor TEXT, payload TEXT)',
    );
    await env.DB.prepare(
      'INSERT INTO forgeedge_config (updated_at, actor, payload) VALUES (?, ?, ?)',
    ).bind(new Date().toISOString(), actor, JSON.stringify(cfg)).run();
  } catch (e) {
    console.log('[forgeedge] D1 mirror skipped:', e instanceof Error ? e.message : String(e));
  }
}

export async function getJSON<T>(env: Env, key: string): Promise<T | null> {
  return kvGetJSON<T>(env, key);
}

export async function putJSON(env: Env, key: string, value: unknown): Promise<void> {
  await env.KV.put(key, JSON.stringify(value));
}
