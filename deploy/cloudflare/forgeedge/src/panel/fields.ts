/**
 * The panel's field table: every configurable key, with the type and the words
 * the operator sees.
 *
 * This exists because the panel used to render the entire configuration as one
 * raw JSON textarea. Every capability below was already implemented and
 * reachable — sixty-odd keys, several of them things no comparable panel has —
 * and all of them were invisible unless you had read the schema. A control the
 * operator cannot find is a feature that was not shipped.
 *
 * It is a TABLE rather than sixty hand-written form blocks so that the UI and
 * the schema cannot drift apart in the usual way: a key added to EdgeConfig with
 * no row here shows up in the Expert tab's JSON and nowhere else, which is
 * exactly the state this replaces. `panel-fields.test.ts` compares the two and
 * fails on any key with no row.
 *
 * `path` is dotted and addresses the config object directly, so binding needs no
 * per-field code.
 */

export type FieldKind = 'text' | 'password' | 'number' | 'bool' | 'select' | 'lines' | 'csv';

export interface Field {
  path: string;
  label: string;
  kind: FieldKind;
  /** Shown under the control. Say what it does and what it costs, not what it is. */
  help?: string;
  options?: readonly string[];
  placeholder?: string;
  min?: number;
  max?: number;
  /** Marks a control whose effect is destructive or easy to misjudge. */
  caution?: boolean;
}

export interface Group {
  id: string;
  title: string;
  /** One line under the group title. */
  blurb?: string;
  fields: Field[];
}

export const GROUPS: readonly Group[] = [
  {
    id: 'identity',
    title: 'Identity',
    blurb: 'What the edge advertises, and the credentials it falls back to when a subscriber has none of their own.',
    fields: [
      { path: 'protocols', label: 'Protocols advertised', kind: 'csv', placeholder: 'vless,trojan',
        help: 'vless, trojan, or both.' },
      { path: 'vlessUUID', label: 'VLESS UUID', kind: 'text',
        help: 'Used only for subscribers with no per-user credentials in the feed.' },
      { path: 'trojanPassword', label: 'Trojan password', kind: 'password' },
      { path: 'wsPathSalt', label: 'WebSocket path salt', kind: 'password',
        help: 'Mixed into the generated path so it is stable but unguessable. Changing it changes every path.',
        caution: true },
    ],
  },
  {
    id: 'addressing',
    title: 'Addressing',
    blurb: 'Where clients connect, and which ports the subscription offers.',
    fields: [
      { path: 'customDomain', label: 'Custom domain', kind: 'text', placeholder: 'edge.example.com',
        help: 'An extra hostname this Worker also answers on.' },
      { path: 'ports', label: 'Ports advertised', kind: 'csv', placeholder: '443,2053,2083',
        help: 'Only these appear in the subscription. A port Cloudflare does not route is a config that silently fails.' },
      { path: 'httpsPorts', label: 'TLS ports available', kind: 'csv', placeholder: '443,2053,2083,2087,2096,8443' },
      { path: 'httpPorts', label: 'Plain-HTTP ports available', kind: 'csv', placeholder: '80,8080,8880,2052,2082,2086,2095' },
      { path: 'enableIPv6', label: 'Offer IPv6 addresses', kind: 'bool' },
      { path: 'enableTFO', label: 'TCP Fast Open', kind: 'bool' },
      { path: 'fingerprint', label: 'uTLS fingerprint', kind: 'select',
        options: ['chrome', 'firefox', 'safari', 'ios', 'android', 'edge', 'random', 'randomized'],
        help: 'The TLS handshake clients imitate.' },
    ],
  },
  {
    id: 'cleanips',
    title: 'Clean IPs and CDN fronting',
    blurb: 'Which Cloudflare edge addresses clients dial. The single biggest lever when an ISP blocks the obvious ones.',
    fields: [
      { path: 'cleanIPs', label: 'Clean IPs', kind: 'lines', placeholder: 'cf.090227.xyz\n104.16.0.1',
        help: 'One host or host:port per line.' },
      { path: 'cleanIPSources', label: 'Sources to merge', kind: 'lines',
        help: 'Remote lists pulled in by the scheduled refresh.' },
      { path: 'cleanIPRefresh', label: 'Refresh on a schedule', kind: 'bool' },
      { path: 'cleanIPRandomCount', label: 'Random edge IPs per refresh', kind: 'number', min: 0, max: 64,
        help: '0 uses only the lists above.' },
      { path: 'customCdnAddrs', label: 'Custom CDN addresses', kind: 'lines' },
      { path: 'customCdnHost', label: 'Custom CDN host', kind: 'text' },
      { path: 'customCdnSni', label: 'Custom CDN SNI', kind: 'text' },
      { path: 'externalSubs', label: 'External subscriptions', kind: 'lines',
        help: 'Other subscription URLs merged into this one, so a single link carries your whole fleet.' },
    ],
  },
  {
    id: 'outbound',
    title: 'Outbound path',
    blurb: 'How the edge reaches the destination. Cloudflare refuses direct connections to its own ranges, which is what proxyIP and NAT64 exist to work around.',
    fields: [
      { path: 'proxyIPMode', label: 'Proxy IP mode', kind: 'select', options: ['off', 'proxyip', 'nat64'],
        help: 'off dials directly and cannot reach Cloudflare-hosted destinations.' },
      { path: 'proxyIPs', label: 'Proxy IPs', kind: 'lines' },
      { path: 'nat64Prefixes', label: 'NAT64 prefixes', kind: 'lines' },
      { path: 'chainProxy', label: 'Chain proxy URI', kind: 'text',
        placeholder: 'vless://… | trojan://… | ss://… | socks5://… | http://…',
        help: 'Sends traffic out through a fixed upstream, so the exit IP is one you choose rather than Cloudflare’s.' },
      { path: 'backend.enabled', label: 'Backend mode', kind: 'bool',
        help: 'Hand the tunnel to a ForgePanel VPS instead of terminating it at the edge.' },
      { path: 'backend.url', label: 'Backend URL', kind: 'text', placeholder: 'https://node.example.com/forgeedge' },
      { path: 'backend.token', label: 'Backend token', kind: 'password' },
      { path: 'backend.fallbackToEdge', label: 'Fall back to the edge', kind: 'bool',
        help: 'If the backend refuses the upgrade, terminate here rather than failing the connection.' },
    ],
  },
  {
    id: 'limits',
    title: 'Limits',
    blurb: 'Bounds on edge-terminated traffic. Per-isolate accounting, and Backend Mode is not counted — see protocols/limits.ts.',
    fields: [
      { path: 'limits.enabled', label: 'Enforce limits', kind: 'bool',
        help: 'Off admits every upgrade and counts nothing.' },
      { path: 'limits.perIPConcurrent', label: 'Concurrent sockets per IP', kind: 'number', min: 0, max: 4096 },
      { path: 'limits.perIPNewPerMinute', label: 'New connections per IP per minute', kind: 'number', min: 0, max: 10000 },
      { path: 'limits.perUUIDConcurrent', label: 'Concurrent sockets per credential', kind: 'number', min: 0, max: 4096,
        help: 'Declared but NOT enforced. The key exists with its final shape; nothing reads it yet.' },
    ],
  },
  {
    id: 'obfuscation',
    title: 'Obfuscation',
    blurb: 'What the client does to its own handshake. These are emitted into the client config; the edge does not perform them.',
    fields: [
      { path: 'fragment.enabled', label: 'TLS fragmentation', kind: 'bool',
        help: 'Splits the TLS hello so DPI cannot match it whole.' },
      { path: 'fragment.packets', label: 'Packets', kind: 'select', options: ['tlshello', '1-1', '1-2', '1-3', '1-5'] },
      { path: 'fragment.lengthMin', label: 'Length min', kind: 'number', min: 0 },
      { path: 'fragment.lengthMax', label: 'Length max', kind: 'number', min: 0 },
      { path: 'fragment.delayMin', label: 'Delay min (ms)', kind: 'number', min: 0 },
      { path: 'fragment.delayMax', label: 'Delay max (ms)', kind: 'number', min: 0 },
      { path: 'fragment.maxSplitMin', label: 'Max split min', kind: 'number', min: 0 },
      { path: 'fragment.maxSplitMax', label: 'Max split max', kind: 'number', min: 0 },
      { path: 'enableECH', label: 'Encrypted Client Hello', kind: 'bool',
        help: 'Hides the SNI. Only clients that support ECH benefit.' },
      { path: 'echServerName', label: 'ECH server name', kind: 'text' },
    ],
  },
  {
    id: 'dns',
    title: 'DNS',
    blurb: 'Resolvers written into client configs, plus the upstream this Worker’s own /dns-query proxies to.',
    fields: [
      { path: 'remoteDNS', label: 'Remote DNS', kind: 'text', placeholder: 'https://dns.google/dns-query' },
      { path: 'localDNS', label: 'Local DNS', kind: 'text', placeholder: '8.8.8.8' },
      { path: 'antiSanctionDNS', label: 'Anti-sanction DNS', kind: 'text',
        help: 'Used for domains that geo-block Iran, so they resolve locally and exit locally.' },
      { path: 'dohUpstream', label: 'DoH upstream', kind: 'text',
        help: 'What this Worker’s own private DoH server forwards to.' },
      { path: 'fakeDNS', label: 'Fake DNS', kind: 'bool' },
    ],
  },
  {
    id: 'routing',
    title: 'Routing rules',
    blurb: 'Bypass sends traffic out directly instead of through the tunnel. Block drops it.',
    fields: [
      { path: 'routing.bypassLAN', label: 'Bypass LAN', kind: 'bool' },
      { path: 'routing.bypassIran', label: 'Bypass Iran', kind: 'bool' },
      { path: 'routing.bypassChina', label: 'Bypass China', kind: 'bool' },
      { path: 'routing.bypassRussia', label: 'Bypass Russia', kind: 'bool' },
      { path: 'routing.bypassSanctions', label: 'Bypass sanctioned domains', kind: 'bool',
        help: 'Services that geo-block Iran must exit locally or they refuse the connection.' },
      { path: 'routing.blockQUIC', label: 'Block QUIC', kind: 'bool',
        help: 'Forces clients onto TCP. Useful where UDP is throttled; costs you HTTP/3.' },
      { path: 'routing.blockAds', label: 'Block ads', kind: 'bool' },
      { path: 'routing.blockMalware', label: 'Block malware', kind: 'bool' },
      { path: 'routing.blockPhishing', label: 'Block phishing', kind: 'bool' },
      { path: 'routing.blockCryptominers', label: 'Block cryptominers', kind: 'bool' },
      { path: 'routing.blockPorn', label: 'Block adult sites', kind: 'bool' },
      { path: 'routing.customBypassRules', label: 'Custom bypass', kind: 'lines' },
      { path: 'routing.customBypassSanctionRules', label: 'Custom sanction bypass', kind: 'lines' },
      { path: 'routing.customBlockRules', label: 'Custom block', kind: 'lines' },
    ],
  },
  {
    id: 'warp',
    title: 'WARP',
    blurb: 'Cloudflare WARP as WireGuard and AmneziaWG nodes. Accounts are registered off the edge — a Worker cannot register them itself.',
    fields: [
      { path: 'warp.endpoints', label: 'Endpoints', kind: 'lines' },
      { path: 'warp.remoteDNS', label: 'WARP DNS', kind: 'text' },
      { path: 'warp.reservedBytes', label: 'Send reserved bytes', kind: 'bool',
        help: 'Cloudflare drops the session without them.' },
      { path: 'warp.bestPingInterval', label: 'Best-ping interval (s)', kind: 'number', min: 10, max: 3600 },
      { path: 'warp.amneziaNoiseCount', label: 'Amnezia noise count', kind: 'number', min: 0 },
      { path: 'warp.amneziaNoiseSizeMin', label: 'Amnezia noise size min', kind: 'number', min: 0 },
      { path: 'warp.amneziaNoiseSizeMax', label: 'Amnezia noise size max', kind: 'number', min: 0 },
      { path: 'warp.knockerNoiseMode', label: 'Knocker noise mode', kind: 'text' },
      { path: 'warp.knockerNoiseCountMin', label: 'Knocker count min', kind: 'number', min: 0 },
      { path: 'warp.knockerNoiseCountMax', label: 'Knocker count max', kind: 'number', min: 0 },
      { path: 'warp.knockerNoiseSizeMin', label: 'Knocker size min', kind: 'number', min: 0 },
      { path: 'warp.knockerNoiseSizeMax', label: 'Knocker size max', kind: 'number', min: 0 },
      { path: 'warp.knockerNoiseDelayMin', label: 'Knocker delay min', kind: 'number', min: 0 },
      { path: 'warp.knockerNoiseDelayMax', label: 'Knocker delay max', kind: 'number', min: 0 },
    ],
  },
  {
    id: 'subscription',
    title: 'Subscription',
    blurb: 'How the generated nodes are named and where the canonical feed comes from.',
    fields: [
      { path: 'subTitle', label: 'Subscription title', kind: 'text' },
      { path: 'remarkStyle', label: 'Remark style', kind: 'select', options: ['fancy', 'plain'] },
      { path: 'remarkPrefix', label: 'Remark prefix', kind: 'text', placeholder: 'ForgeEdge' },
      { path: 'bestPingInterval', label: 'Best-ping interval (s)', kind: 'number', min: 10, max: 3600,
        help: 'How often clients re-test the auto-select group.' },
      { path: 'feedPullURL', label: 'Feed pull URL', kind: 'text',
        help: 'The ForgePanel VPS this Worker pulls its canonical node list from.' },
      { path: 'feedPullToken', label: 'Feed pull token', kind: 'password' },
    ],
  },
  {
    id: 'panel',
    title: 'Panel',
    blurb: 'This administration surface, and what an unauthenticated visitor sees.',
    fields: [
      { path: 'fallbackHost', label: 'Fallback host', kind: 'text', placeholder: 'example.com',
        help: 'Served for any unmatched path, so a scanner finds a real site rather than a proxy.' },
      { path: 'logLevel', label: 'Log level', kind: 'select', options: ['none', 'warning', 'error', 'info', 'debug'] },
      { path: 'telegramBotToken', label: 'Telegram bot token', kind: 'password' },
      { path: 'telegramUserID', label: 'Telegram user ID', kind: 'text' },
      { path: 'autoUpdateCheck', label: 'Check for updates', kind: 'bool' },
      { path: 'updateRepo', label: 'Update repository', kind: 'text' },
    ],
  },
] as const;

/** Every path the form binds, for the drift test and for the save path. */
export function allPaths(): string[] {
  return GROUPS.flatMap((g) => g.fields.map((f) => f.path));
}
