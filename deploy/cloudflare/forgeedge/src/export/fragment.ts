/**
 * Client-side evasion knobs: TLS fragmentation, UDP noise, and ECH.
 *
 * None of these belong to the canonical node — they describe how the CLIENT
 * should emit packets, not what the server is. Keeping them out of `model.Node`
 * is what lets the Go panel and the edge stay in sync on the node model while
 * the edge still ships an obfuscated client config. They are applied to a
 * rendered outbound, after the canonical render, by the functions here.
 */

import type { FragmentConfig, XrayUDPNoise } from '../config/schema';
import type { JSONValue } from './gojson';

type JObj = Record<string, JSONValue>;

/** `min-max`, or a bare number when both ends are equal, or undefined when unset. */
export function toRange(min: number, max: number): string | undefined {
  if (!min && !max) return undefined;
  if (min === max) return String(min);
  return `${min}-${max}`;
}

/** Xray `finalmask.udp[].settings.noise[]` entries, expanded by `count`. */
export function buildUDPNoises(noises: XrayUDPNoise[]): JObj[] {
  const out: JObj[] = [];
  for (const { type, packet, delay, count } of noises) {
    const noise: JObj = type === 'rand'
      ? { rand: packet, randRange: '0-255', delay }
      : { type, packet: type === 'array' ? packet.split(',').map(Number) : packet, delay };
    for (let i = 0; i < Math.max(1, count); i++) out.push({ ...noise });
  }
  return out;
}

export interface FinalMaskOptions {
  fragment?: FragmentConfig;
  udpNoises?: XrayUDPNoise[];
  /** Override the fragment length for the "smart fragment" sweep. */
  lengthOverride?: string;
  delayOverride?: string;
}

/**
 * Xray 26 `streamSettings.finalmask`. Returns undefined when neither
 * fragmentation nor noise is enabled, so the key is simply absent.
 */
export function buildFinalMask(opts: FinalMaskOptions): JObj | undefined {
  const frag = opts.fragment;
  const noises = opts.udpNoises ?? [];
  const wantFrag = !!frag?.enabled;
  const wantNoise = noises.length > 0;
  if (!wantFrag && !wantNoise) return undefined;

  const mask: JObj = {};
  if (wantFrag && frag) {
    const settings: JObj = {
      packets: frag.packets,
      length: opts.lengthOverride ?? toRange(frag.lengthMin, frag.lengthMax) ?? '100-200',
      delay: opts.delayOverride ?? toRange(frag.delayMin, frag.delayMax) ?? '1-1',
    };
    const maxSplit = toRange(frag.maxSplitMin, frag.maxSplitMax);
    if (maxSplit) settings.maxSplit = maxSplit;
    mask.tcp = [{ type: 'fragment', settings }];
  }
  if (wantNoise) {
    mask.udp = [{ type: 'noise', settings: { reset: '30-60', noise: buildUDPNoises(noises) } }];
  }
  return mask;
}

/** Attach the mask to an already-rendered Xray outbound, in place. */
export function applyXrayFinalMask(outbound: JObj, opts: FinalMaskOptions): JObj {
  const mask = buildFinalMask(opts);
  if (!mask) return outbound;
  const ss = (outbound.streamSettings as JObj | undefined) ?? {};
  ss.finalmask = mask;
  outbound.streamSettings = ss;
  return outbound;
}

/**
 * sing-box has no `finalmask`; its equivalent of TLS fragmentation is the
 * boolean `tls.record_fragment`. Applying it to an outbound without TLS would
 * be rejected as an unknown key on a missing object, so it is a no-op there.
 */
export function applySingboxFragment(outbound: JObj, frag: FragmentConfig | undefined): JObj {
  if (!frag?.enabled) return outbound;
  const tls = outbound.tls as JObj | undefined;
  if (!tls) return outbound;
  tls.record_fragment = true;
  return outbound;
}

/**
 * ECH for an Xray outbound. Xray takes `echConfigList` as either a literal
 * base64 ECHConfigList or a `[serverName+]udp://resolver` locator that makes the
 * core fetch the HTTPS RR itself — the latter is what works without pinning a
 * config that rotates.
 */
export function applyXrayECH(outbound: JObj, enabled: boolean, echServerName: string, dns: string): JObj {
  if (!enabled) return outbound;
  const ss = outbound.streamSettings as JObj | undefined;
  if (!ss) return outbound;
  const tls = ss.tlsSettings as JObj | undefined;
  if (!tls) return outbound;
  const resolver = dns === 'localhost' || !dns ? '8.8.8.8' : dns;
  tls.echConfigList = echServerName ? `${echServerName}+udp://${resolver}` : `udp://${resolver}`;
  return outbound;
}
