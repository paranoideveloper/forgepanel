/**
 * "Serverless" / "workerless" configs — the edgetunnel/BPB trick for the worst
 * case, when EVERY proxy IP is blocked. There is no proxy here at all: the whole
 * config is Xray `freedom` outbounds whose `finalmask` fragments the TLS
 * ClientHello (and adds UDP noise), so a DIRECT connection slips past an
 * SNI-matching DPI box. It only helps when the destination is reachable
 * directly-but-filtered (a great deal of CDN-hosted content in Iran), not when
 * the IP itself is null-routed — but it needs nothing from us to keep working.
 *
 * This is Xray-only: BPB ships no sing-box equivalent because `finalmask` is an
 * Xray feature and sing-box's `tls.record_fragment` only fragments a tunnel's
 * own TLS, not a direct connection's. The config reuses the exact skeleton of
 * the normal Xray subscription (proven core-valid by the golden/AcceptedByCore
 * tests) and only swaps the outbounds + routing.
 */

import type { EdgeConfig } from '../config/schema';
import type { JSONValue } from './gojson';
import { goMarshalIndent } from './gojson';
import type { JObj } from './singbox';
import { toRange, buildUDPNoises } from './fragment';

const URLTEST_URL = 'https://www.gstatic.com/generate_204';

/** The two upstreams edgetunnel/BPB point serverless at, by resolver IP. */
export interface ServerlessVariant {
  id: string;
  remark: string;
  /** Plain-DNS resolver the local dokodemo forwards to (kept resilient). */
  dnsIP: string;
}

export const SERVERLESS_VARIANTS: ServerlessVariant[] = [
  { id: 'cf', remark: '💦 1 · Serverless · Cloudflare 🌟', dnsIP: '1.1.1.1' },
  { id: 'google', remark: '💦 2 · Serverless · Google 🌟', dnsIP: '8.8.8.8' },
];

/** Resolve a variant by id, defaulting to Cloudflare. */
export function serverlessVariant(id: string | undefined): ServerlessVariant {
  return SERVERLESS_VARIANTS.find((v) => v.id === id) ?? SERVERLESS_VARIANTS[0];
}

/** A `freedom` outbound whose finalmask fragments the TLS ClientHello. */
function freedomFragment(tag: string, packets: string, length: string, delay: string, tfo: boolean): JObj {
  return {
    protocol: 'freedom',
    tag,
    settings: {},
    streamSettings: {
      sockopt: { tcpFastOpen: tfo, domainStrategy: 'UseIP' },
      finalmask: { tcp: [{ type: 'fragment', settings: { packets, length, delay } }] },
    },
  };
}

/** A `freedom` outbound that prepends UDP noise packets. */
function freedomNoise(tag: string, cfg: EdgeConfig): JObj {
  return {
    protocol: 'freedom',
    tag,
    settings: {},
    streamSettings: {
      finalmask: { udp: [{ type: 'noise', settings: { reset: '30-60', noise: buildUDPNoises(cfg.udpNoises) } }] },
    },
  };
}

/**
 * Build one serverless Xray config. All TCP defaults through the TLS-fragmenting
 * `proxy` outbound (Xray sends unmatched traffic to the first outbound); plain
 * HTTP (port 80) rides a coarser 1-byte fragment; UDP gets noise; DNS is
 * hijacked to the freedom `dns-out`.
 */
export function buildServerlessXray(cfg: EdgeConfig, variant: ServerlessVariant): string {
  const frag = cfg.fragment;
  const length = toRange(frag.lengthMin, frag.lengthMax) ?? '100-200';
  const delay = toRange(frag.delayMin, frag.delayMax) ?? '1-1';

  const doc: JObj = {
    log: { loglevel: cfg.logLevel === 'warning' ? 'warning' : cfg.logLevel },
    inbounds: [
      { tag: 'socks', port: 10808, listen: '127.0.0.1', protocol: 'socks', settings: { udp: true, auth: 'noauth' } },
      { tag: 'http', port: 10809, listen: '127.0.0.1', protocol: 'http' },
      { tag: 'dns-in', port: 10853, listen: '127.0.0.1', protocol: 'dokodemo-door', settings: { address: variant.dnsIP, port: 53, network: 'tcp,udp' } },
    ] as unknown as JSONValue,
    // Order matters: `proxy` (the TLS fragmenter) is first, so any traffic no
    // rule matches defaults to it.
    outbounds: [
      freedomFragment('proxy', 'tlshello', length, delay, cfg.enableTFO),
      freedomFragment('http-fragment', '1-1', '1-1', '1-1', cfg.enableTFO),
      freedomNoise('udp-noise', cfg),
      { protocol: 'dns', tag: 'dns-out', settings: { rules: [{ action: 'hijack' }] } },
      { protocol: 'blackhole', tag: 'block', settings: { response: { type: 'http' } } },
    ] as unknown as JSONValue,
    routing: {
      domainStrategy: 'IPIfNonMatch',
      rules: [
        { inboundTag: ['dns-in'], outboundTag: 'dns-out' },
        { protocol: ['dns'], outboundTag: 'dns-out' },
        { network: 'udp', port: '443', outboundTag: 'block' }, // QUIC would bypass the fragmenter
        { network: 'udp', outboundTag: 'udp-noise' },
        { network: 'tcp', port: '80', outboundTag: 'http-fragment' },
      ] as unknown as JSONValue,
    },
    remarks: variant.remark,
  };
  return goMarshalIndent(doc as unknown as JSONValue, '  ');
}

export { URLTEST_URL as SERVERLESS_URLTEST };
