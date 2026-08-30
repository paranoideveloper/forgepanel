export interface User {
  id: number;
  username: string;
  group_id?: number;
  sub_token: string;
  enabled: boolean;
  notes?: string;
  created_at?: string;
  traffic_used_gb?: number;
  traffic_limit_gb?: number;
  expire_at?: string;
}

export interface UserGroup {
  id: number;
  name: string;
  description?: string;
  max_users?: number;
}

// Mirrors store.Node exactly. It previously declared last_heartbeat and
// active_users, which the Go model does not have (it reports last_seen), while
// omitting everything the API does send — so the fields the UI read were always
// undefined and the fields the server sent were invisible.
export interface Node {
  id: number;
  name: string;
  address: string;
  enrolled: boolean;
  last_seen?: string | null;
  core_version?: string;
  cpu: number;
  mem_mb: number;
  disk_used_mb?: number;
  disk_total_mb?: number;
  tcp_conns?: number;
  core_uptime_sec?: number;
  healthy: boolean;
  config_dirty?: boolean;
  config_dirty_at?: string | null;
  /** Where the node is in its life, derived server-side on every read.
   *
   *  `healthy` is one bit and the table needed four states: a node mid-install,
   *  a node that has died, a node whose core is refusing its config, and one an
   *  operator switched off all rendered the same "Stale" badge. Only the server
   *  can tell them apart — nothing in last_seen says a node was disabled or that
   *  its core is failing. */
  status: 'connecting' | 'connected' | 'error' | 'disabled';
  /** Why, in the node's own words where it has any. */
  status_message?: string;
  /** Switched off by an operator. The panel refuses its heartbeats, so it stops
   *  receiving config bundles rather than merely looking off in the list. */
  disabled?: boolean;
}

export interface DNSZone {
  id: number;
  zone: string;
  adapter: string;
  enabled: boolean;
  ns_host?: string;
  domains?: string;
  bind_host?: string;
  bind_port?: number;
  mode?: string;
}

// Client bundle returned by /forgedns/zones/:id/bundle — the delegation records
// to paste at the registrar plus the ready-to-use client config file.
export interface DNSBundle {
  zone: string;
  adapter: string;
  ns_host: string;
  ns_records: Array<{ type: string; name: string; value: string; note?: string }>;
  cloudflare_warning?: string;
  client_config_toml: string;
  client_resolvers_txt?: string;
  socks5?: string;
  steps?: string[];
  releases_page?: string;
}

export interface DNSAdapter {
  id: string;
  name: string;
  description: string;
}

export interface SystemHealth {
  version: string;
  status: string;
  uptime_seconds: number;
  nodes_online: number;
  nodes_total: number;
  cpu_usage?: number;
  mem_usage?: number;
}

export interface HealthDetail {
  subsystems: Array<{
    key: string;
    label: string;
    state: string;   // healthy | not_configured | degraded | error
    summary: string;
    detail?: string;
    link?: string;
  }>;
}

export interface EngineStatus {
  name: string;
  version: string;
  running: boolean;
  inbounds_count: number;
}

export interface CertStatus {
  domain: string;
  status: string;
  valid_until?: string;
  issuer?: string;
  auto_tls: boolean;
}

export interface ProtocolPreset {
  id: string;
  name: string;
  engine: string;
  description: string;
  config: Record<string, any>;
}

export interface KeygenResult {
  private_key: string;
  public_key: string;
  short_ids?: string[];
}

export interface SetupStatus {
  initialized: boolean;
  admin_created: boolean;
}

export interface TwoFASetup {
  secret: string;
  qr_code_url: string;
  qr_svg?: string;
}

// Mirrors store.AuditLog. It previously declared `timestamp` and `details`,
// neither of which the Go model has, so every field the UI read was undefined
// and every field the server sent was invisible.
export interface AuditLog {
  id: number;
  created_at: string;
  admin_id: number;
  actor: string;
  ip: string;
  action: string;
  target: string;
  diff: string;
}

export interface AuditPage {
  items: AuditLog[];
  total: number;
  limit: number;
  offset: number;
}
