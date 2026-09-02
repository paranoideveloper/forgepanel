/**
 * "Smart Fragment" — the edgetunnel/BPB sweep. The optimal TLS-fragment length
 * is ISP- and DPI-box-specific: a single `100-200` often loses where `20-40`
 * wins, and vice-versa. So we emit the SAME VLESS-over-WS proxy to the worker
 * many times, each with a different fragment length, in one leastPing group —
 * the client measures them all and pins the winner automatically.
 *
 * Xray-only (fragmentation lives in `finalmask`). Delivered as a self-contained
 * config, so it can be imported as a single "smart" profile.
 */

import type { EdgeConfig } from '../config/schema';
import type { JSONValue } from './gojson';
import { goMarshalIndent } from './gojson';
import type { JObj } from './singbox';
import { xrayOutbound } from './xray';
import { toRange } from './fragment';
import type { Node } from '../model/node';

const URLTEST_URL = 'https://www.gstatic.com/generate_204';

/** BPB's length sweep: short→long plus a spread of mid ranges. */
export const SMART_FRAGMENT_LENGTHS = [
  '1-5', '1-10', '10-20', '20-30', '30-40', '40-50', '50-60', '60-70', '70-80', '80-90',
  '90-100', '10-30', '20-40', '30-50', '40-60', '50-70', '60-80', '70-90', '80-100', '100-200',
];

/**
 * Build a self-contained Xray config that fans `node` (a VLESS-over-WS proxy to
 * the worker) across every fragment length, grouped by leastPing. `node` is
 * rendered once by the real exporter, then cloned per length so every variant
 * stays byte-identical except for the fragment.
 */
export function buildSmartFragmentXray(cfg: EdgeConfig, node: Node, title: string): string {
  const base = xrayOutbound(node);
  const delay = toRange(cfg.fragment.delayMin, cfg.fragment.delayMax) ?? '1-1';

  const outbounds: JObj[] = [];
  const tags: string[] = [];
  for (const len of SMART_FRAGMENT_LENGTHS) {
    const o = JSON.parse(JSON.stringify(base)) as JObj;
    const tag = `frag ${len}`;
    o.tag = tag;
    const ss = (o.streamSettings as JObj | undefined) ?? {};
    ss.finalmask = { tcp: [{ type: 'fragment', settings: { packets: 'tlshello', length: len, delay } }] };
    ss.sockopt = { ...((ss.sockopt as JObj | undefined) ?? {}), tcpFastOpen: cfg.enableTFO, domainStrategy: 'UseIP' };
    o.streamSettings = ss;
    outbounds.push(o);
    tags.push(tag);
  }

  const doc: JObj = {
    log: { loglevel: cfg.logLevel === 'warning' ? 'warning' : cfg.logLevel },
    inbounds: [
      { tag: 'socks', port: 10808, listen: '127.0.0.1', protocol: 'socks', settings: { udp: true, auth: 'noauth' } },
      { tag: 'http', port: 10809, listen: '127.0.0.1', protocol: 'http' },
      { tag: 'dns-in', port: 10853, listen: '127.0.0.1', protocol: 'dokodemo-door', settings: { address: '1.1.1.1', port: 53, network: 'tcp,udp' } },
    ] as unknown as JSONValue,
    outbounds: [
      ...outbounds,
      { protocol: 'dns', tag: 'dns-out', settings: { rules: [{ action: 'hijack' }] } },
      { protocol: 'freedom', tag: 'direct', settings: { domainStrategy: cfg.enableIPv6 ? 'UseIPv4v6' : 'UseIPv4' } },
      { protocol: 'blackhole', tag: 'block', settings: { response: { type: 'http' } } },
    ] as unknown as JSONValue,
    routing: {
      domainStrategy: 'IPIfNonMatch',
      rules: [
        { inboundTag: ['dns-in'], outboundTag: 'dns-out' },
        { protocol: ['dns'], outboundTag: 'dns-out' },
        { network: 'tcp,udp', balancerTag: 'smart' },
      ] as unknown as JSONValue,
      balancers: [{ tag: 'smart', selector: tags, strategy: { type: 'leastPing' } }] as unknown as JSONValue,
    },
    observatory: {
      subjectSelector: tags,
      probeURL: URLTEST_URL,
      probeInterval: `${cfg.bestPingInterval}s`,
      enableConcurrency: true,
    },
    remarks: `💦 ${title} · Smart Fragment 🧠`,
  };
  return goMarshalIndent(doc as unknown as JSONValue, '  ');
}
