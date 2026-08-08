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

export interface Node {
  id: number;
  name: string;
  address: string;
  cpu: number;
  mem_mb: number;
  healthy: boolean;
  last_heartbeat?: string;
  active_users?: number;
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

export interface AuditLog {
  id: number;
  timestamp: string;
  actor: string;
  action: string;
  details: string;
}
