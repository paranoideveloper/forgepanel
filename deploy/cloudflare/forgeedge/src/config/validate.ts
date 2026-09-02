/**
 * Config validation.
 *
 * A whole PUT is rejected rather than partially applied: a config carrying a
 * broken chain proxy or a junk clean-IP entry would corrupt every subscription
 * rendered after it, and a half-saved config is harder to reason about than a
 * refused one. Every problem is reported at once so the operator fixes the form
 * in one pass instead of playing whack-a-mole.
 *
 * Pure by design — no bindings, no sockets — so it is unit-testable and can be
 * reused by `forgectl edge` on the Go side if the lead wants a pre-flight check.
 */

import type { EdgeConfig } from './schema';
import { isValidCleanEntry } from '../cleanip/list';
import { parseChainProxy } from '../edge/chain';
import { safeError } from '../common/http';

export function validateConfig(cfg: EdgeConfig): string[] {
  const errors: string[] = [];

  if (!Array.isArray(cfg.protocols) || cfg.protocols.length === 0) {
    errors.push('protocols must list at least one of "vless", "trojan"');
  } else if (cfg.protocols.some((p) => p !== 'vless' && p !== 'trojan')) {
    errors.push('protocols may only contain "vless" and "trojan" (the edge terminates nothing else)');
  }

  if (!Array.isArray(cfg.ports) || cfg.ports.length === 0) {
    errors.push('ports must not be empty');
  } else {
    const allowed = new Set([...(cfg.httpPorts ?? []), ...(cfg.httpsPorts ?? [])]);
    for (const p of cfg.ports) {
      if (!allowed.has(p)) errors.push(`port ${p} is not a Cloudflare-reachable port`);
    }
  }

  if (cfg.vlessUUID && !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(cfg.vlessUUID)) {
    errors.push('vlessUUID is not a valid UUID');
  }
  if ((cfg.protocols ?? []).includes('trojan') && !cfg.trojanPassword) {
    errors.push('trojanPassword is required when trojan is advertised');
  }

  for (const entry of cfg.cleanIPs ?? []) {
    if (!isValidCleanEntry(entry)) errors.push(`cleanIPs entry "${entry}" is not a host or IP`);
  }
  for (const entry of cfg.customCdnAddrs ?? []) {
    if (!isValidCleanEntry(entry)) errors.push(`customCdnAddrs entry "${entry}" is not a host or IP`);
  }
  for (const url of cfg.cleanIPSources ?? []) {
    try {
      const u = new URL(url);
      if (u.protocol !== 'https:') errors.push(`cleanIPSources entry "${url}" must be https`);
    } catch {
      errors.push(`cleanIPSources entry "${url}" is not a URL`);
    }
  }

  if (cfg.chainProxy) {
    try { parseChainProxy(cfg.chainProxy); } catch (e) { errors.push(`chainProxy: ${safeError(e)}`); }
  }

  if (cfg.backend?.enabled) {
    if (!cfg.backend.url) {
      errors.push('backend.enabled requires backend.url');
    } else {
      try {
        const u = new URL(cfg.backend.url);
        if (!['http:', 'https:', 'ws:', 'wss:'].includes(u.protocol)) {
          errors.push('backend.url must be http(s):// or ws(s)://');
        }
      } catch { errors.push('backend.url is not a URL'); }
    }
  }

  if (cfg.proxyIPMode === 'nat64' && (cfg.nat64Prefixes ?? []).length === 0) {
    errors.push('proxyIPMode "nat64" needs at least one nat64Prefixes entry');
  }
  if (cfg.proxyIPMode === 'proxyip' && (cfg.proxyIPs ?? []).length === 0) {
    errors.push('proxyIPMode "proxyip" needs at least one proxyIPs entry');
  }
  for (const p of cfg.nat64Prefixes ?? []) {
    if (!/^\[[0-9A-Fa-f:]+\]$/.test(p)) errors.push(`nat64 prefix "${p}" must be a bracketed IPv6 prefix`);
  }

  if (cfg.fragment?.enabled) {
    if (cfg.fragment.lengthMin > cfg.fragment.lengthMax) errors.push('fragment.lengthMin must not exceed lengthMax');
    if (cfg.fragment.delayMin > cfg.fragment.delayMax) errors.push('fragment.delayMin must not exceed delayMax');
  }

  if (cfg.bestPingInterval !== undefined && cfg.bestPingInterval < 5) {
    errors.push('bestPingInterval below 5s will hammer the probe URL');
  }

  // The panel edits `limits` through a free-form JSON box, so this is the only
  // thing standing between a typo and a Worker that refuses every connection.
  const limits = cfg.limits;
  if (limits) {
    for (const key of ['perIPConcurrent', 'perIPNewPerMinute', 'perUUIDConcurrent'] as const) {
      const v = limits[key];
      if (!Number.isInteger(v) || v < 1) errors.push(`limits.${key} must be a positive integer`);
    }
    if (typeof limits.enabled !== 'boolean') errors.push('limits.enabled must be a boolean');
  }

  return errors;
}
