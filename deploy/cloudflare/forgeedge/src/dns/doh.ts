/**
 * DoH relay at `/<securePath>/dns-query`.
 *
 * Clients configured with this URL get DNS that leaves from the Worker rather
 * than from the user's ISP resolver, which is the whole point in a network that
 * poisons DNS. Both wire formats are supported: GET with `?dns=` or `?name=`,
 * and POST with `application/dns-message`.
 */

import { HttpStatus } from '../common/http';

export async function handleDoH(request: Request, upstream: string): Promise<Response> {
  const target = new URL(upstream || 'https://cloudflare-dns.com/dns-query');
  const incoming = new URL(request.url);
  for (const [k, v] of incoming.searchParams) target.searchParams.set(k, v);

  const headers = new Headers();
  const accept = request.headers.get('accept');
  const ct = request.headers.get('content-type');
  if (accept) headers.set('accept', accept);
  if (ct) headers.set('content-type', ct);

  if (request.method === 'POST') {
    const body = await request.arrayBuffer();
    return fetch(target.toString(), { method: 'POST', headers, body });
  }
  if (request.method === 'GET') {
    return fetch(target.toString(), { method: 'GET', headers });
  }
  return new Response('Method Not Allowed', { status: HttpStatus.METHOD_NOT_ALLOWED });
}
