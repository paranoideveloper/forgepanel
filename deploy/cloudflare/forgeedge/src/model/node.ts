/**
 * THE canonical representation of a proxy node, mirrored field-for-field from
 * the Go source of truth at `internal/protocol/model/model.go`.
 *
 * The Go struct is the authority. Every property name here is the Go struct
 * tag's JSON name, so `JSON.parse(json.Marshal(*model.Node))` is assignable to
 * `Node` with no translation layer, and a `Node` built here marshals back into
 * a Go `model.Node` unchanged. Adding a field on either side without the other
 * is the one way to break the edge/VPS subscription contract — see
 * `docs/GO_WIRING.md`.
 *
 *   parse/  ──►  Node  ──►  render/  (xray json, sing-box json)
 *                     ──►  export/  (vless://, clash yaml, sing-box, links)
 */

/** Protocol discriminator. Values are the stable strings used in Go's JSON, the DB and the registry. */
export type Protocol =
  | 'vless'
  | 'vmess'
  | 'trojan'
  | 'shadowsocks'
  | 'socks'
  | 'http'
  | 'hysteria2'
  | 'tuic'
  | 'anytls'
  | 'wireguard'
  | 'amneziawg'
  | 'shadowtls'
  | 'ssh'
  | 'brook'
  | 'forgedns';

/** Mirror of Go `model.AllProtocols()` — note AmneziaWG is deliberately absent there too. */
export const ALL_PROTOCOLS: Protocol[] = [
  'vless', 'vmess', 'trojan', 'shadowsocks', 'socks',
  'http', 'hysteria2', 'tuic', 'anytls', 'wireguard',
  'shadowtls', 'ssh', 'brook', 'forgedns',
];

export type Network = 'tcp' | 'ws' | 'grpc' | 'httpupgrade' | 'xhttp' | 'h2' | 'kcp' | 'quic';

export const ALL_NETWORKS: Network[] = ['tcp', 'ws', 'grpc', 'httpupgrade', 'xhttp', 'h2', 'kcp', 'quic'];

export type SecurityType = 'none' | 'tls' | 'reality';

export const ALL_SECURITY_TYPES: SecurityType[] = ['none', 'tls', 'reality'];

// Shadowsocks methods (model.go const block).
export const SS2022_AES128 = '2022-blake3-aes-128-gcm';
export const SS2022_AES256 = '2022-blake3-aes-256-gcm';
export const SS2022_CHACHA20 = '2022-blake3-chacha20-poly1305';
export const SS_AES256_GCM = 'aes-256-gcm';
export const SS_AES128_GCM = 'aes-128-gcm';
export const SS_CHACHA20_POLY = 'chacha20-ietf-poly1305';
export const SS_XCHACHA20_POLY = 'xchacha20-ietf-poly1305';
export const SS_NONE = 'none';

export const ALL_SHADOWSOCKS_METHODS: string[] = [
  SS2022_AES128, SS2022_AES256, SS2022_CHACHA20,
  SS_AES256_GCM, SS_AES128_GCM, SS_CHACHA20_POLY, SS_XCHACHA20_POLY, SS_NONE,
];

/** Mirror of `model.KeySizeForMethod`: raw key length in bytes, and whether it is SIP022. */
export function keySizeForMethod(method: string): { size: number; is2022: boolean } {
  switch (method) {
    case SS2022_AES128: return { size: 16, is2022: true };
    case SS2022_AES256:
    case SS2022_CHACHA20: return { size: 32, is2022: true };
    case SS_AES128_GCM: return { size: 16, is2022: false };
    case SS_AES256_GCM:
    case SS_CHACHA20_POLY:
    case SS_XCHACHA20_POLY: return { size: 32, is2022: false };
    default: return { size: 0, is2022: false };
  }
}

/** `model.Header` — obfuscation header for tcp/mkcp/quic. */
export interface Header {
  type?: string;
  request?: Record<string, string[]>;
  host?: string[];
  path?: string[];
  method?: string;
}

/** `model.XMux` — xhttp multiplexing parameters (all string-typed in Go, ranges like "16-32"). */
export interface XMux {
  max_concurrency?: string;
  max_connections?: string;
  c_max_reuse_times?: string;
  c_max_lifetime_ms?: string;
  h_max_request_times?: string;
  h_keep_alive_period?: number;
}

/** `model.Transport` — every transport knob, orthogonal to protocol. */
export interface Transport {
  network: Network;

  // ws / httpupgrade / xhttp / h2
  path?: string;
  host?: string;
  headers?: Record<string, string>;
  early_data?: number;
  ed_header?: string;

  // grpc
  service_name?: string;
  multi_mode?: boolean;
  idle_timeout?: number;
  health_check?: boolean;
  initial_windows?: number;
  permit_without_stream?: boolean;

  // xhttp / splithttp
  xhttp_mode?: string;
  x_padding_bytes?: string;
  xmux?: XMux;

  // h2
  h2_hosts?: string[];

  // tcp / mkcp / quic obfuscation
  header?: Header;

  // mkcp
  seed?: string;
  mtu?: number;
  tti?: number;
  uplink_capacity?: number;
  downlink_capacity?: number;
  congestion?: boolean;
  read_buffer_size?: number;
  write_buffer_size?: number;

  // quic
  quic_security?: string;
  quic_key?: string;
}

/** `model.ECH` — Encrypted Client Hello. */
export interface ECH {
  enabled?: boolean;
  config_list?: string;
  auto_fetch?: boolean;
}

/** `model.Reality`. `private_key` is server-only and must never reach a client link. */
export interface Reality {
  dest?: string;
  server_names?: string[];
  private_key?: string;
  public_key?: string;
  short_ids?: string[];
  short_id?: string;
  spider_x?: string;
  xver?: number;
  mldsa65_seed?: string;
  mldsa65_verify?: string;
}

/** `model.Security` — the TLS layer: none, TLS, or REALITY. */
export interface Security {
  type: SecurityType;
  server_name?: string;
  alpn?: string[];
  fingerprint?: string;
  allow_insecure?: boolean;
  min_version?: string;
  max_version?: string;
  cipher_suites?: string;
  certificate_file?: string;
  key_file?: string;
  pin_sha256?: string[];
  reality?: Reality;
  ech?: ECH;
}

/** Mirror of `model.ValidFingerprints()`. */
export const VALID_FINGERPRINTS: string[] = [
  'chrome', 'firefox', 'safari', 'ios', 'android', 'edge', '360', 'qq', 'random', 'randomized',
];

/** `model.Brutal` — TCP Brutal congestion control. */
export interface Brutal {
  enabled?: boolean;
  up_mbps?: number;
  down_mbps?: number;
}

/** `model.Multiplex` — covers both mux.cool (xray) and sing-box mux. */
export interface Multiplex {
  enabled?: boolean;
  protocol?: string;
  max_connections?: number;
  min_streams?: number;
  max_streams?: number;
  padding?: boolean;
  concurrency?: number;
  brutal?: Brutal;
}

/** `model.Hy2Masquerade`. */
export interface Hy2Masquerade {
  type?: string;
  url?: string;
  rewrite_host?: boolean;
  directory?: string;
  status_code?: number;
  headers?: Record<string, string>;
  content?: string;
}

/** `model.Hysteria2Options`. */
export interface Hysteria2Options {
  up_mbps?: number;
  down_mbps?: number;
  obfs_type?: string;
  obfs_password?: string;
  port_hopping?: string;
  port_hop_interval?: number;
  ignore_client_bandwidth?: boolean;
  masquerade?: Hy2Masquerade;
  /** legacy, migrated into `masquerade` by normalize() */
  masquerade_type?: string;
  /** legacy, migrated into `masquerade` by normalize() */
  masquerade_url?: string;
  hop_interval_max?: number;
  /** PANEL preset flag only — never rendered (sing-box has no such field). */
  brutal_cc?: boolean;
}

/** `model.TUICOptions`. */
export interface TUICOptions {
  congestion_control?: string;
  udp_relay_mode?: string;
  zero_rtt_handshake?: boolean;
  heartbeat?: number;
  disable_sni?: boolean;
}

/** `model.AnyTLSOptions`. */
export interface AnyTLSOptions {
  padding_scheme?: string[];
  idle_session_check_interval?: number;
  idle_session_timeout?: number;
  min_idle_sessions?: number;
}

/** `model.WireGuardOptions`. */
export interface WireGuardOptions {
  private_key?: string;
  public_key?: string;
  server_address?: string[];
  peer_private_key?: string;
  peer_public_key?: string;
  peer_address?: string[];
  pre_shared_key?: string;
  allowed_ips?: string[];
  mtu?: number;
  persistent_keepalive?: number;
  reserved?: number[];
  workers?: number;
  /** legacy field name kept for parse/back-compat; maps to server_address when set. */
  local_address?: string[];
}

/**
 * `model.AmneziaWGOptions` — embeds WireGuardOptions in Go, which inlines those
 * fields into the same JSON object, so `extends` is the exact mirror.
 */
export interface AmneziaWGOptions extends WireGuardOptions {
  jc?: number;
  jmin?: number;
  jmax?: number;
  s1?: number;
  s2?: number;
  h1?: number;
  h2?: number;
  h3?: number;
  h4?: number;
}

/** `model.ShadowTLSOptions`. */
export interface ShadowTLSOptions {
  version?: number;
  password?: string;
  handshake_host?: string;
  handshake_port?: number;
  strict_mode?: boolean;
  inner_method?: string;
  inner_password?: string;
}

/** `model.SSHOptions`. */
export interface SSHOptions {
  user?: string;
  password?: string;
  private_key?: string;
  private_key_passphrase?: string;
  host_key_algorithms?: string[];
  client_version?: string;
}

/** `model.BrookOptions`. */
export interface BrookOptions {
  mode?: string;
  path?: string;
  udp_over_tcp?: boolean;
  without_brook_protocol?: boolean;
}

/** `model.ForgeDNSOptions` — DNS-tunnel parameters (spec §5). */
export interface ForgeDNSOptions {
  adapter?: string;
  zone?: string;
  ns_host?: string;
  key?: string;
  rrtype?: string;
  max_upstream?: number;
  max_downstream?: number;
  edns_buffer?: number;
}

/** `model.SSPluginOptions` — a SIP003 Shadowsocks plugin. */
export interface SSPluginOptions {
  name?: string;
  opts?: string;
}

/** `model.Node` — THE canonical representation. */
export interface Node {
  tag?: string;
  remark?: string;
  protocol: Protocol;
  address: string;
  port: number;

  uuid?: string;
  password?: string;
  username?: string;
  method?: string;
  flow?: string;
  encryption?: string;
  alter_id?: number;

  transport: Transport;
  security: Security;
  multiplex?: Multiplex;

  hysteria2?: Hysteria2Options;
  tuic?: TUICOptions;
  anytls?: AnyTLSOptions;
  wireguard?: WireGuardOptions;
  amneziawg?: AmneziaWGOptions;
  shadowtls?: ShadowTLSOptions;
  ssh?: SSHOptions;
  brook?: BrookOptions;
  forgedns?: ForgeDNSOptions;
  ss_plugin?: SSPluginOptions;
}

/** Mirror of `(Protocol).UsesTransport()`. */
export function usesTransport(p: Protocol): boolean {
  switch (p) {
    case 'vless': case 'vmess': case 'trojan':
    case 'shadowsocks': case 'socks': case 'http':
      return true;
    default:
      return false;
  }
}

/** Mirror of `(Protocol).IsQUICBased()`. */
export function isQUICBased(p: Protocol): boolean {
  return p === 'hysteria2' || p === 'tuic';
}

/** Mirror of `(*Node).SNI()`: explicit SNI, else transport Host, else the address. */
export function sni(n: Node): string {
  if (n.security?.server_name) return n.security.server_name;
  if (n.transport?.host) return n.transport.host;
  return n.address;
}

/** Mirror of `render.EngineFor` — which engine serves a protocol on the VPS side. */
export function engineFor(p: Protocol): string {
  switch (p) {
    case 'vless': case 'vmess': case 'trojan':
    case 'shadowsocks': case 'socks': case 'http':
      return 'xray';
    case 'hysteria2': case 'tuic': case 'anytls':
    case 'shadowtls': case 'ssh': case 'wireguard':
      return 'sing-box';
    case 'amneziawg':
      return 'amneziawg';
    case 'brook':
      return 'brook';
    case 'forgedns':
      return 'forgedns';
    default:
      return 'unknown';
  }
}

/** Deep copy, mirroring `(*Node).Clone()` so callers can mutate without aliasing. */
export function cloneNode(n: Node): Node {
  return JSON.parse(JSON.stringify(n)) as Node;
}
