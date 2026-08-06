export interface ApiError {
  message: string;
  status: number;
}

let authToken: string = localStorage.getItem('forge_token') || '';

export function setAuthToken(token: string): void {
  authToken = token;
  if (token) {
    localStorage.setItem('forge_token', token);
  } else {
    localStorage.removeItem('forge_token');
  }
}

export function getAuthToken(): string {
  return authToken;
}

export async function apiFetch<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string> || {})
  };

  if (authToken) {
    headers['Authorization'] = `Bearer ${authToken}`;
  }

  const response = await fetch(`/api${path}`, {
    ...options,
    headers
  });

  if (!response.ok) {
    let errMsg = `HTTP Error ${response.status}`;
    try {
      const data = await response.json();
      if (data.error) errMsg = data.error;
    } catch (_) {}
    throw { message: errMsg, status: response.status } as ApiError;
  }

  return response.json() as Promise<T>;
}
