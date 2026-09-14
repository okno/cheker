const TOKEN_KEY = 'mcp-integrity-guard-token';

export function initialToken(): string {
  const fragment = new URLSearchParams(window.location.hash.slice(1));
  const imported = fragment.get('token');
  if (imported) {
    window.history.replaceState(null, '', window.location.pathname + window.location.search);
    sessionStorage.setItem(TOKEN_KEY, imported);
    return imported;
  }
  return sessionStorage.getItem(TOKEN_KEY) || '';
}

export function saveToken(token: string): void {
  if (token) sessionStorage.setItem(TOKEN_KEY, token);
  else sessionStorage.removeItem(TOKEN_KEY);
}

export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message);
  }
}

export async function request<T>(
  path: string,
  token: string,
  options: RequestInit = {},
): Promise<T> {
  const headers = new Headers(options.headers);
  if (token) headers.set('Authorization', `Bearer ${token}`);
  if (options.body && !(options.body instanceof FormData))
    headers.set('Content-Type', 'application/json');
  let response: Response;
  try {
    response = await fetch(`/api${path}`, {
      ...options,
      headers,
      cache: 'no-store',
      credentials: 'omit',
    });
  } catch {
    throw new ApiError(
      'Backend non raggiungibile. Verifica che MCP Integrity Guard sia avviato su questo dispositivo.',
      0,
    );
  }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail =
      typeof data.detail === 'string'
        ? data.detail
        : JSON.stringify(data.detail || data.error || 'Richiesta non riuscita');
    throw new ApiError(
      response.status === 401
        ? 'Token non valido. Riconnettiti con il token dell’applicazione.'
        : detail,
      response.status,
    );
  }
  return data as T;
}

export function downloadJson(value: unknown, filename: string): void {
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' }),
  );
  const link = document.createElement('a');
  link.href = url;
  link.download = filename.replace(/[^a-zA-Z0-9._-]/g, '_');
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export const serialize = (value: unknown): string =>
  typeof value === 'string' ? value : (JSON.stringify(value, null, 2) ?? '—');
export const dateTime = (value?: string | null): string =>
  value
    ? new Intl.DateTimeFormat('it-CH', { dateStyle: 'short', timeStyle: 'short' }).format(
        new Date(value),
      )
    : '—';
export const shortHash = (value?: string): string =>
  value ? `${value.slice(0, 12)}…${value.slice(-8)}` : '—';
