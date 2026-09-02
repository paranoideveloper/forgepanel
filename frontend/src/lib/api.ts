export interface ApiError {
  message: string;
  status: number;
  /** Machine-readable reason, e.g. "group_in_use" or "quota_exceeded". */
  code?: string;
  /** Per-field rejection reasons, for showing an error under the input that
   *  caused it rather than one toast for the whole form. */
  fields?: Record<string, string>;
  /** What the API says to do about it. */
  remediation?: string;
  /** Classification the whole API now agrees on — "not_found", "permission",
   *  "no_credentials", "stale_write" — so a caller can branch on the reason
   *  instead of pattern-matching the sentence or guessing from the status. */
  kind?: string;
  /** The exact provider permission that was missing, in the wording that
   *  provider's own token editor uses, e.g. "Zone → DNS → Edit". */
  missingScope?: string;
  /** The whole decoded body, for anything the fields above do not name —
   *  `members` on a group conflict, `missing_scope` on a Cloudflare refusal. */
  body?: Record<string, unknown>;
}

// Session handling.
//
// Login returns an access token AND a refresh token, and the panel used to keep
// only the first. So when the access token expired — which it does, by design —
// every request began failing with a bare "HTTP Error 401", the UI filled with
// errors that named no cause, and the only way out was for the operator to
// guess that reloading and signing in again would fix it. The refresh endpoint
// existed the whole time and nothing called it.
//
// Now: a 401 triggers one refresh and a retry. If the refresh fails the session
// is genuinely over, tokens are cleared, and listeners are told so the UI can
// say "your session expired" instead of showing a wall of failures.

const ACCESS_KEY = 'forge_token';
const REFRESH_KEY = 'forge_refresh';

let authToken: string = safeGet(ACCESS_KEY);
let refreshToken: string = safeGet(REFRESH_KEY);

// Reading storage throws in some contexts (private windows, blocked site data),
// and an exception here would break the whole module rather than merely lose a
// remembered session.
function safeGet(key: string): string {
  try {
    return localStorage.getItem(key) || '';
  } catch {
    return '';
  }
}

function safeSet(key: string, value: string): void {
  try {
    if (value) localStorage.setItem(key, value);
    else localStorage.removeItem(key);
  } catch {
    /* the session simply is not remembered across reloads */
  }
}

export function setAuthToken(token: string): void {
  authToken = token;
  safeSet(ACCESS_KEY, token);
}

export function getAuthToken(): string {
  return authToken;
}

/** Store both halves of a login response. */
export function setSession(access: string, refresh?: string): void {
  setAuthToken(access);
  if (refresh !== undefined) {
    refreshToken = refresh;
    safeSet(REFRESH_KEY, refresh);
  }
}

export function clearSession(): void {
  setAuthToken('');
  refreshToken = '';
  safeSet(REFRESH_KEY, '');
}

// Listeners are notified when the session ends for good, so the app can show a
// sign-in prompt rather than letting every in-flight call surface its own error.
type SessionListener = () => void;
const expiredListeners = new Set<SessionListener>();

export function onSessionExpired(fn: SessionListener): () => void {
  expiredListeners.add(fn);
  return () => expiredListeners.delete(fn);
}

function notifyExpired(): void {
  for (const fn of expiredListeners) {
    try {
      fn();
    } catch {
      /* one bad listener must not stop the others being told */
    }
  }
}

// A single in-flight refresh, shared by every caller that hits a 401 at once.
// Without this, a page with six parallel requests fires six refreshes against
// one refresh token — wasteful at best, and mutually invalidating on a backend
// that rotates it.
let refreshInFlight: Promise<boolean> | null = null;

async function refreshAccessToken(): Promise<boolean> {
  if (!refreshToken) return false;
  if (refreshInFlight) return refreshInFlight;

  refreshInFlight = (async () => {
    try {
      const res = await fetch('/api/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refreshToken })
      });
      if (!res.ok) return false;
      const data = await res.json();
      if (!data?.access_token) return false;
      setSession(data.access_token, data.refresh_token);
      return true;
    } catch {
      // A network failure is not an expired session: the caller surfaces the
      // original error and the next attempt can succeed.
      return false;
    } finally {
      refreshInFlight = null;
    }
  })();

  return refreshInFlight;
}

async function toError(response: Response): Promise<ApiError> {
  let message = `HTTP Error ${response.status}`;
  let body: Record<string, unknown> | undefined;
  try {
    const data = await response.json();
    if (data && typeof data === 'object') body = data as Record<string, unknown>;
    if (data?.error) message = data.error;
  } catch {
    /* a non-JSON body leaves the status-based message */
  }
  // Carry the WHOLE body, not just its `error` string.
  //
  // The API answers a refused request with far more than a sentence: `code` for
  // a machine-readable reason (group_in_use), `fields` mapping each rejected
  // field to why, `members` listing what is in the way, `remediation` and
  // `missing_scope`. Collapsing all of it into one string meant a caller could
  // only ever show a toast — no per-field errors under the inputs, and no way
  // to offer the choice the backend is explicitly asking for. Every one of
  // those endpoints was answering a question nothing could hear.
  const err: ApiError = { message, status: response.status };
  if (body) {
    err.body = body;
    if (typeof body.code === 'string') err.code = body.code;
    if (body.fields && typeof body.fields === 'object') {
      err.fields = body.fields as Record<string, string>;
    }
    if (typeof body.remediation === 'string') err.remediation = body.remediation;
    // kind and missing_scope reached the browser and were dropped here.
    //
    // The backend now types every refusal, and the two most useful fields were
    // the two nothing lifted: a Cloudflare rejection arrived carrying the exact
    // checkbox to tick and the UI could only show its sentence. Reading them
    // costs two lines and is the difference between "Forbidden" and "your API
    // token is missing Zone → DNS → Edit".
    if (typeof body.kind === 'string') err.kind = body.kind;
    if (typeof body.missing_scope === 'string') {
      err.missingScope = body.missing_scope;
      // Also fold it into the message. Seventy-odd views toast `e.message` and
      // nothing else; a field none of them read yet would leave the operator
      // looking at "Forbidden" while the answer sat one property away.
      err.message = `${message} — missing permission: ${body.missing_scope}`;
    }
  }
  return err;
}

export async function apiFetch<T>(path: string, options: RequestInit = {}): Promise<T> {
  const send = async (): Promise<Response> => {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...((options.headers as Record<string, string>) || {})
    };
    if (authToken) headers['Authorization'] = `Bearer ${authToken}`;
    return fetch(`/api${path}`, { ...options, headers });
  };

  let response = await send();

  // One refresh, one retry. Refreshing on the refresh call itself would loop,
  // and retrying more than once turns an expired session into a storm of
  // requests that all fail anyway.
  if (response.status === 401 && path !== '/refresh' && refreshToken) {
    if (await refreshAccessToken()) {
      response = await send();
    } else {
      clearSession();
      notifyExpired();
    }
  } else if (response.status === 401 && path !== '/refresh') {
    // No refresh token to try: the session is over.
    clearSession();
    notifyExpired();
  }

  if (!response.ok) throw await toError(response);

  // A genuinely empty body is a SUCCESS: a 204 from a delete used to reject
  // with a JSON syntax error and read to the caller as a failed request.
  //
  // Only 204/205 qualify. A MALFORMED body must still reject: swallowing a
  // parse failure into `undefined` hands the caller a value that looks like a
  // successful empty response, and it then carries on with missing data — the
  // silent-failure shape this codebase has been removing everywhere else.
  if (response.status === 204 || response.status === 205) return undefined as T;
  return (await response.json()) as T;
}
