/**
 * Panel authentication and the compulsory secure-path gate.
 *
 * Two independent layers, and both are required:
 *
 *  1. SECURE PATH — every panel, API and subscription URL lives under a random
 *     path segment. An attacker who does not have it cannot even see that a
 *     panel exists; unmatched paths get the decoy. This is the layer that keeps
 *     internet-wide Worker scanners from finding the login form at all.
 *  2. SESSION — the panel itself needs the admin password. The secure path is
 *     shared with subscribers indirectly (their sub URLs are under it), so it is
 *     NOT a secret strong enough to stand alone for administration.
 *
 * Sessions are HMAC-SHA256 over a JSON payload, signed with a key in KV. No JWT
 * library: a signed, expiring blob is the entire requirement, and every
 * dependency in a Worker is bytes in the bundle and a supply-chain surface.
 */

import { b64RawURL, b64AnyDecode } from './common/encoding';
import { timingSafeEqual } from './common/http';
import type { EdgeSecrets } from './config/schema';
import { hashPassword } from './config/store';

const TE = new TextEncoder();
const TD = new TextDecoder();

export const SESSION_COOKIE = 'forgeedge_session';
const SESSION_TTL_SECONDS = 12 * 60 * 60;

interface SessionPayload { sub: string; exp: number }

async function hmac(key: string, data: string): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw', TE.encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, TE.encode(data)));
}

export async function issueSession(secrets: EdgeSecrets, subject = 'admin'): Promise<string> {
  const payload: SessionPayload = { sub: subject, exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS };
  const body = b64RawURL(TE.encode(JSON.stringify(payload)));
  const sig = b64RawURL(await hmac(secrets.sessionKey, body));
  return `${body}.${sig}`;
}

export async function verifySession(secrets: EdgeSecrets, token: string | null): Promise<boolean> {
  if (!token) return false;
  const dot = token.lastIndexOf('.');
  if (dot <= 0) return false;
  const body = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const expected = b64RawURL(await hmac(secrets.sessionKey, body));
  if (!timingSafeEqual(sig, expected)) return false;
  try {
    const payload = JSON.parse(TD.decode(b64AnyDecode(body))) as SessionPayload;
    return typeof payload.exp === 'number' && payload.exp > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}

export function readCookie(request: Request, name: string): string | null {
  const header = request.headers.get('Cookie');
  if (!header) return null;
  for (const part of header.split(';')) {
    const [k, ...rest] = part.trim().split('=');
    if (k === name) return rest.join('=');
  }
  return null;
}

export function sessionCookieHeader(token: string, maxAge = SESSION_TTL_SECONDS): string {
  return `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}

export function clearSessionCookie(): string {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

export async function isAuthenticated(request: Request, secrets: EdgeSecrets): Promise<boolean> {
  return verifySession(secrets, readCookie(request, SESSION_COOKIE));
}

export function checkPassword(secrets: EdgeSecrets, password: string): boolean {
  if (!secrets.adminHash) return false;
  return timingSafeEqual(hashPassword(secrets.adminSalt, password), secrets.adminHash);
}

/**
 * The secure-path gate.
 *
 * Returns the remaining path segments when the FIRST segment matches, else null.
 * The comparison is constant-time so a caller cannot binary-search the path one
 * character at a time by timing the 404.
 */
export function matchSecurePath(pathname: string, securePath: string): string[] | null {
  const segments = pathname.split('/').filter((s) => s.length > 0);
  if (segments.length === 0) return null;
  const decoded = safeDecode(segments[0]);
  if (!timingSafeEqual(decoded, securePath)) return null;
  return segments.slice(1);
}

function safeDecode(s: string): string {
  try { return decodeURIComponent(s); } catch { return s; }
}
