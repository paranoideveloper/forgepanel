/** Small HTTP helpers shared by every handler. */

export enum HttpStatus {
  OK = 200,
  NO_CONTENT = 204,
  MOVED = 302,
  BAD_REQUEST = 400,
  UNAUTHORIZED = 401,
  FORBIDDEN = 403,
  NOT_FOUND = 404,
  METHOD_NOT_ALLOWED = 405,
  CONFLICT = 409,
  TOO_MANY = 429,
  INTERNAL = 500,
  BAD_GATEWAY = 502,
}

export interface ApiEnvelope<T = unknown> {
  success: boolean;
  status: number;
  message: string | null;
  body: T | null;
}

export function respond<T>(
  success: boolean,
  status: HttpStatus,
  message?: string,
  body?: T,
  extraHeaders?: Record<string, string>,
): Response {
  const payload: ApiEnvelope<T> = {
    success, status, message: message ?? null, body: body ?? null,
  };
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...extraHeaders },
  });
}

/** Headers every subscription response must carry. */
export function subscriptionHeaders(
  filename: string,
  contentType: string,
  profileTitleB64: string,
  userinfo: string,
): Record<string, string> {
  return {
    'Content-Type': contentType,
    'Content-Disposition': `attachment; filename=${filename}`,
    // The body varies by User-Agent while the URL stays constant. Without both
    // of these an intermediate cache could serve one subscriber's credentials
    // to another, or hand a sing-box client a Clash body.
    'Vary': 'User-Agent',
    'Cache-Control': 'no-store, no-cache, must-revalidate, private',
    'Pragma': 'no-cache',
    'Expires': '0',
    'Profile-Update-Interval': '12',
    'Profile-Title': `base64:${profileTitleB64}`,
    'Subscription-Userinfo': userinfo,
    'Access-Control-Allow-Origin': '*',
  };
}

/** Constant-time string comparison for secrets that appear in a URL path. */
export function timingSafeEqual(a: string, b: string): boolean {
  // Length is compared without early-exit so the loop below always runs.
  let diff = a.length ^ b.length;
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) {
    diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }
  return diff === 0;
}

export function safeError(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
