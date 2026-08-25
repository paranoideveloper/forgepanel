export interface ApiError {
  message: string;
  status: number;
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
  try {
    const data = await response.json();
    if (data?.error) message = data.error;
  } catch {
    /* a non-JSON body leaves the status-based message */
  }
  return { message, status: response.status };
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
