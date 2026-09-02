/**
 * Outbound retry POLICY, kept free of `cloudflare:sockets`.
 *
 * A Cloudflare Worker cannot reach every destination directly: Cloudflare's own
 * IP ranges are unreachable from a Worker, and some hosts refuse a Cloudflare
 * source address. Two escape hatches, both operator-configurable:
 *
 *   proxyip — retry through a relay host that terminates TCP for us.
 *   nat64   — resolve the destination to IPv4 and rewrite it into a NAT64 /64,
 *             so the Worker dials an IPv6 literal a public NAT64 gateway
 *             translates back.
 *
 * This file is deliberately import-clean: choosing the retry target is pure
 * policy, and pure policy is what the unit tests can exercise without workerd.
 * The socket work lives in outbound.ts.
 */

import { parseHostPort, toNAT64, isIPv4 } from '../common/net';
import { resolveIPv4 } from '../dns/resolve';
import type { ProxyIPMode } from '../config/schema';

export interface OutboundOptions {
  proxyIPMode: ProxyIPMode;
  proxyIPs: string[];
  nat64Prefixes: string[];
  dohUpstream: string;
}

const pick = <T>(arr: T[]): T | undefined =>
  arr.length === 0 ? undefined : arr[Math.floor(Math.random() * arr.length)];

/**
 * The retry destination for the configured escape hatch, or null when there is
 * none. Null is a real answer: it means the caller must close the connection
 * with an error rather than silently connecting somewhere else.
 */
export async function retryTarget(
  address: string,
  port: number,
  opts: OutboundOptions,
): Promise<{ address: string; port: number } | null> {
  if (opts.proxyIPMode === 'proxyip') {
    const raw = pick(opts.proxyIPs);
    if (!raw) return null;
    const { host, port: p } = parseHostPort(raw, true);
    return { address: host || address, port: p || port };
  }

  if (opts.proxyIPMode === 'nat64') {
    // Prefer the FIRST prefix rather than a random one: public NAT64 gateways
    // vary wildly in health, so the operator orders the list best-first and a
    // random pick would land on a dead gateway most of the time (a ~19s hang).
    const prefix = opts.nat64Prefixes[0];
    if (!prefix) return null;
    let v4 = address;
    if (!isIPv4(address)) {
      const resolved = await resolveIPv4(address, opts.dohUpstream);
      if (resolved.length === 0) return null;
      v4 = resolved[0];
    }
    const mapped = toNAT64(v4, prefix);
    return mapped ? { address: mapped, port } : null;
  }

  return null;
}
