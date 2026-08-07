/** DNS-over-HTTPS lookups used by the outbound path and the config builder. */

interface DohAnswer { type: number; data: string }
interface DohResponse { Answer?: DohAnswer[] }

const DEFAULT_DOH = 'https://cloudflare-dns.com/dns-query';

async function query(name: string, type: 'A' | 'AAAA', upstream: string): Promise<string[]> {
  const base = upstream || DEFAULT_DOH;
  const url = `${base}?name=${encodeURIComponent(name)}&type=${type}`;
  const res = await fetch(url, { headers: { accept: 'application/dns-json' } });
  if (!res.ok) return [];
  const data = (await res.json()) as DohResponse;
  if (!data.Answer) return [];
  const want = type === 'A' ? 1 : 28;
  return data.Answer.filter((a) => a.type === want).map((a) => a.data);
}

export async function resolveIPv4(name: string, upstream = DEFAULT_DOH): Promise<string[]> {
  try { return await query(name, 'A', upstream); } catch { return []; }
}

export async function resolveIPv6(name: string, upstream = DEFAULT_DOH): Promise<string[]> {
  try { return await query(name, 'AAAA', upstream); } catch { return []; }
}

export async function resolveDNS(
  name: string, onlyIPv4 = false, upstream = DEFAULT_DOH,
): Promise<{ ipv4: string[]; ipv6: string[] }> {
  const ipv4 = await resolveIPv4(name, upstream);
  const ipv6 = onlyIPv4 ? [] : await resolveIPv6(name, upstream);
  return { ipv4, ipv6 };
}
