/**
 * ForgeEdge's entire runtime configuration.
 *
 * DESIGN RULE: no required dashboard environment variables. Everything below
 * lives in KV (optionally mirrored to D1) and is editable from the panel. The
 * only thing the operator must keep is the secure path, which is minted on first
 * boot and can be regenerated from the panel.
 */

export const CONFIG_VERSION = 1;

/** KV keys. Namespaced so a shared namespace stays legible. */
export const KV_KEYS = {
  config: 'forgeedge:config',
  secrets: 'forgeedge:secrets',
  feed: 'forgeedge:feed',
  warp: 'forgeedge:warp',
  cleanIPs: 'forgeedge:cleanips',
  updateCheck: 'forgeedge:update',
} as const;

export type ProxyIPMode = 'off' | 'proxyip' | 'nat64';
export type FragmentPacket = 'tlshello' | '1-1' | '1-2' | '1-3' | '1-5';
export type LogLevel = 'none' | 'warning' | 'error' | 'info' | 'debug';

export interface XrayUDPNoise {
  type: 'rand' | 'str' | 'base64' | 'hex' | 'array';
  packet: string;
  delay: string;
  count: number;
}

/** Everything the routing rulesets can be toggled by (spec: §6 routing rulesets). */
export interface RoutingConfig {
  bypassLAN: boolean;
  bypassIran: boolean;
  bypassChina: boolean;
  bypassRussia: boolean;
  /** "sanctioned domains" — services that geo-block Iran and must exit locally. */
  bypassSanctions: boolean;
  blockQUIC: boolean;
  blockAds: boolean;
  blockMalware: boolean;
  blockPhishing: boolean;
  blockCryptominers: boolean;
  blockPorn: boolean;
  customBypassRules: string[];
  customBypassSanctionRules: string[];
  customBlockRules: string[];
}

/** A ForgePanel VPS node reachable for Backend Mode. */
export interface BackendConfig {
  /** Master switch. When off the Worker terminates VLESS/Trojan itself. */
  enabled: boolean;
  /** `https://node.example.com/forgeedge` — the WS endpoint on the user's Xray/sing-box VPS. */
  url: string;
  /** Optional bearer presented to the backend's control endpoints (scan/health). */
  token: string;
  /** Fall back to edge termination if the backend refuses the upgrade. */
  fallbackToEdge: boolean;
}

export interface WarpConfig {
  endpoints: string[];
  remoteDNS: string;
  reservedBytes: boolean;
  bestPingInterval: number;
  /** AmneziaWG obfuscation for the "pro" variant. */
  amneziaNoiseCount: number;
  amneziaNoiseSizeMin: number;
  amneziaNoiseSizeMax: number;
  /** Xray-knocker WireGuard noise (v2rayN-PRO / MahsaNG). */
  knockerNoiseMode: string;
  knockerNoiseCountMin: number;
  knockerNoiseCountMax: number;
  knockerNoiseSizeMin: number;
  knockerNoiseSizeMax: number;
  knockerNoiseDelayMin: number;
  knockerNoiseDelayMax: number;
}

export interface FragmentConfig {
  enabled: boolean;
  packets: FragmentPacket;
  lengthMin: number;
  lengthMax: number;
  delayMin: number;
  delayMax: number;
  maxSplitMin: number;
  maxSplitMax: number;
}

export interface EdgeConfig {
  version: number;

  // --- identity handed to clients -----------------------------------------
  /** Fallback credentials used when a subscriber has no per-user credentials in the feed. */
  vlessUUID: string;
  trojanPassword: string;
  /** Salt mixed into the generated WS path so paths are stable but unguessable. */
  wsPathSalt: string;
  /** Which protocols the edge advertises. */
  protocols: ('vless' | 'trojan')[];

  // --- addressing ----------------------------------------------------------
  /** Extra hostname the Worker is also reachable on (custom domain). */
  customDomain: string;
  httpPorts: number[];
  httpsPorts: number[];
  /** Ports actually advertised in the subscription. */
  ports: number[];
  enableIPv6: boolean;
  enableTFO: boolean;
  fingerprint: string;

  // --- clean IPs / CDN fronting -------------------------------------------
  cleanIPs: string[];
  /** Remote lists merged into cleanIPs by the scheduled refresh. */
  cleanIPSources: string[];
  cleanIPRefresh: boolean;
  /** How many fresh random Cloudflare edge IPs to mint each refresh (0 = none). */
  cleanIPRandomCount: number;
  customCdnAddrs: string[];
  customCdnHost: string;
  customCdnSni: string;

  // --- outbound path -------------------------------------------------------
  proxyIPMode: ProxyIPMode;
  proxyIPs: string[];
  nat64Prefixes: string[];
  backend: BackendConfig;
  /** Chain proxy URI (vless/trojan/ss/socks/http) that fixes the exit IP. */
  chainProxy: string;

  // --- obfuscation emitted into client configs ----------------------------
  fragment: FragmentConfig;
  udpNoises: XrayUDPNoise[];
  enableECH: boolean;
  echServerName: string;

  // --- DNS -----------------------------------------------------------------
  remoteDNS: string;
  localDNS: string;
  antiSanctionDNS: string;
  /** Upstream the Worker's own /dns-query proxies to. */
  dohUpstream: string;
  fakeDNS: boolean;

  routing: RoutingConfig;
  warp: WarpConfig;

  // --- subscription --------------------------------------------------------
  subTitle: string;
  /** Remark styling for the edge's own nodes: 'fancy' (emoji, default) or 'plain'. */
  remarkStyle: 'fancy' | 'plain';
  /** Brand shown in each remark (default 'ForgeEdge'). */
  remarkPrefix: string;
  bestPingInterval: number;
  /** Pull the canonical node feed from the ForgePanel VPS on a schedule. */
  feedPullURL: string;
  feedPullToken: string;

  // --- panel ---------------------------------------------------------------
  /** Host served for any unmatched path, so a scanner sees a real site. */
  fallbackHost: string;
  logLevel: LogLevel;
  telegramBotToken: string;
  telegramUserID: string;
  /** Check GitHub for a newer ForgeEdge release on the cron trigger. */
  autoUpdateCheck: boolean;
  updateRepo: string;
}

/** Secrets, kept in a separate KV key so a config export never leaks them. */
export interface EdgeSecrets {
  /** COMPULSORY random path gating the panel and every subscription URL. */
  securePath: string;
  /** HMAC key for panel session cookies. */
  sessionKey: string;
  /** Bearer the ForgePanel VPS presents when pushing the canonical feed. */
  feedPushToken: string;
  /** Argon-less but salted: sha256(salt + password). Empty until first setup. */
  adminSalt: string;
  adminHash: string;
  createdAt: string;
  rotatedAt: string;
}

export const DEFAULT_ROUTING: RoutingConfig = {
  bypassLAN: true,
  bypassIran: true,
  bypassChina: false,
  bypassRussia: false,
  bypassSanctions: true,
  blockQUIC: false,
  blockAds: false,
  blockMalware: true,
  blockPhishing: true,
  blockCryptominers: false,
  blockPorn: false,
  customBypassRules: [],
  customBypassSanctionRules: [],
  customBlockRules: [],
};

export const DEFAULT_WARP: WarpConfig = {
  endpoints: ['engage.cloudflareclient.com:2408'],
  remoteDNS: '1.1.1.1',
  reservedBytes: true,
  bestPingInterval: 30,
  amneziaNoiseCount: 5,
  amneziaNoiseSizeMin: 50,
  amneziaNoiseSizeMax: 100,
  knockerNoiseMode: 'quic',
  knockerNoiseCountMin: 10,
  knockerNoiseCountMax: 15,
  knockerNoiseSizeMin: 5,
  knockerNoiseSizeMax: 10,
  knockerNoiseDelayMin: 1,
  knockerNoiseDelayMax: 1,
};

export const DEFAULT_FRAGMENT: FragmentConfig = {
  enabled: false,
  packets: 'tlshello',
  lengthMin: 100,
  lengthMax: 200,
  delayMin: 1,
  delayMax: 1,
  maxSplitMin: 0,
  maxSplitMax: 0,
};

/**
 * Cloudflare's TLS-terminating ports. A Worker is reachable on all of these, and
 * spreading a subscription across them is the cheapest way to survive a
 * port-specific block.
 */
export const CF_HTTPS_PORTS = [443, 8443, 2053, 2083, 2087, 2096];
export const CF_HTTP_PORTS = [80, 8080, 2052, 2082, 2086, 2095, 8880];

export function defaultConfig(): EdgeConfig {
  return {
    version: CONFIG_VERSION,
    vlessUUID: '',
    trojanPassword: '',
    wsPathSalt: '',
    protocols: ['vless', 'trojan'],

    customDomain: '',
    httpPorts: [...CF_HTTP_PORTS],
    httpsPorts: [...CF_HTTPS_PORTS],
    // Spread across every Cloudflare TLS port, not just 443. When an Iranian ISP
    // throttles or blocks 443, the client's best-ping group still has 2053/2087/
    // 8443/etc. to fall back to. The list is de-duped and port-filtered downstream.
    ports: [...CF_HTTPS_PORTS],
    enableIPv6: false,
    enableTFO: false,
    fingerprint: 'chrome',

    cleanIPs: [],
    cleanIPSources: [],
    cleanIPRefresh: true,
    // ~30% of random CF-range IPs are live HTTP edges; mint 10 so a handful land
    // and the client's best-ping group can pick them (the dead ones are skipped).
    cleanIPRandomCount: 10,
    customCdnAddrs: [],
    customCdnHost: '',
    customCdnSni: '',

    // proxyIP/NAT64 is the escape hatch for the CF→CF refusal — a Worker's
    // connect() to a Cloudflare IP is refused, so Cloudflare-hosted destinations
    // are otherwise unreachable through the edge. It stays OFF by default on
    // purpose: measured live, the public NAT64 gateways below answer only ~25%
    // of the time and hang ~19s (a socket timeout) the rest, which is worse for
    // the user than a fast failure. Turn it on when you have a RELIABLE gateway
    // or, better, point `proxyIPs` at an SNI-routing relay you run on your own
    // fleet (`proxyIPMode: 'proxyip'`). When NAT64 IS enabled the retry uses the
    // FIRST prefix, so the list is ordered best-first.
    proxyIPMode: 'off',
    proxyIPs: [],
    nat64Prefixes: ['[2602:fc59:11:64::]', '[2602:fc59:b0:64::]', '[2a02:898:146:64::]'],
    backend: { enabled: false, url: '', token: '', fallbackToEdge: true },
    chainProxy: '',

    fragment: { ...DEFAULT_FRAGMENT },
    udpNoises: [{ type: 'rand', packet: '50-100', delay: '1-5', count: 5 }],
    enableECH: false,
    echServerName: '',

    remoteDNS: 'https://8.8.8.8/dns-query',
    localDNS: '8.8.8.8',
    antiSanctionDNS: '178.22.122.100',
    dohUpstream: 'https://cloudflare-dns.com/dns-query',
    fakeDNS: false,

    routing: { ...DEFAULT_ROUTING },
    warp: { ...DEFAULT_WARP },

    subTitle: 'ForgeEdge',
    remarkStyle: 'fancy',
    remarkPrefix: 'ForgeEdge',
    bestPingInterval: 30,
    feedPullURL: '',
    feedPullToken: '',

    fallbackHost: '',
    logLevel: 'warning',
    telegramBotToken: '',
    telegramUserID: '',
    autoUpdateCheck: true,
    updateRepo: 'forgepanel/forgepanel',
  };
}
