/**
 * Cloudflare API operations the panel exposes: deploy, update, delete, status —
 * for both Workers and Pages.
 *
 * CREDENTIAL POLICY. There are two ways to authorise these, and they are NOT
 * equivalent:
 *
 *   OAuth (preferred) — `forgectl edge deploy` runs a PKCE flow against
 *     dash.cloudflare.com and holds the resulting token on the operator's own
 *     machine. Nothing is ever written into the Worker. This is the default and
 *     the only flow that needs no long-lived secret anywhere.
 *
 *   Token fallback — an API token can be supplied as the `CF_API_TOKEN` binding
 *     for operators who want the panel itself to self-update or self-delete. A
 *     token stored in a Worker binding is readable by anyone who can deploy to
 *     that account, so this is opt-in and the panel says so.
 *
 * When neither is present the panel still works completely; only the
 * self-management buttons are unavailable, and they report exactly why.
 */

import { safeError } from '../common/http';

export interface CfCredentials {
  accountID: string;
  apiToken: string;
}

export type DeployTarget = 'workers' | 'pages';

export interface DeployStatus {
  target: DeployTarget;
  name: string;
  exists: boolean;
  /** workers.dev / pages.dev hostnames plus any custom domains. */
  hostnames: string[];
  lastDeployed?: string;
  error?: string;
}

interface CfEnvelope<T> { success: boolean; result: T; errors?: { message: string }[] }

async function cfFetch<T>(
  creds: CfCredentials, path: string, init: RequestInit = {},
): Promise<T> {
  const res = await fetch(`https://api.cloudflare.com/client/v4${path}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${creds.apiToken}`,
      ...(init.body instanceof FormData ? {} : { 'Content-Type': 'application/json' }),
      ...(init.headers ?? {}),
    },
  });
  const data = (await res.json()) as CfEnvelope<T>;
  if (!data.success) throw new Error(data.errors?.[0]?.message ?? `Cloudflare API returned ${res.status}`);
  return data.result;
}

// --- Workers ---------------------------------------------------------------

export async function deployWorker(
  creds: CfCredentials, name: string, script: string, kvNamespaceID?: string,
): Promise<void> {
  const bindings = kvNamespaceID
    ? [{ type: 'kv_namespace', name: 'KV', namespace_id: kvNamespaceID }]
    : undefined;
  const metadata = {
    main_module: 'worker.js',
    compatibility_date: new Date().toISOString().split('T')[0],
    compatibility_flags: ['nodejs_compat'],
    // Without keep_bindings an update would silently detach KV and every
    // subscriber's config would vanish on the next request.
    keep_bindings: ['kv_namespace', 'd1'],
    ...(bindings ? { bindings } : {}),
  };
  const form = new FormData();
  form.append('metadata', new Blob([JSON.stringify(metadata)], { type: 'application/json' }));
  form.append('worker.js', new Blob([script], { type: 'application/javascript+module' }), 'worker.js');
  await cfFetch(creds, `/accounts/${creds.accountID}/workers/scripts/${name}`, { method: 'PUT', body: form });
}

export async function deleteWorker(creds: CfCredentials, name: string): Promise<void> {
  await cfFetch(creds, `/accounts/${creds.accountID}/workers/scripts/${name}`, { method: 'DELETE' });
}

export async function workerDomains(creds: CfCredentials, name: string): Promise<string[]> {
  const result = await cfFetch<{ hostname: string }[]>(
    creds, `/accounts/${creds.accountID}/workers/domains?service=${encodeURIComponent(name)}`);
  return result.map((r) => r.hostname);
}

export async function setWorkerDomain(
  creds: CfCredentials, name: string, hostname: string, zoneID: string,
): Promise<void> {
  await cfFetch(creds, `/accounts/${creds.accountID}/workers/domains`, {
    method: 'PUT',
    body: JSON.stringify({ hostname, service: name, environment: 'production', zone_id: zoneID }),
  });
}

// --- Pages -----------------------------------------------------------------

export async function deployPages(creds: CfCredentials, project: string, script: string): Promise<void> {
  const form = new FormData();
  form.append('manifest', '{}');
  form.append('_worker.js', new Blob([script], { type: 'application/javascript' }), '_worker.js');
  await cfFetch(creds, `/accounts/${creds.accountID}/pages/projects/${project}/deployments`, {
    method: 'POST', body: form,
  });
}

export async function deletePagesProject(creds: CfCredentials, project: string): Promise<void> {
  await cfFetch(creds, `/accounts/${creds.accountID}/pages/projects/${project}`, { method: 'DELETE' });
}

export async function pagesDomains(creds: CfCredentials, project: string): Promise<string[]> {
  const result = await cfFetch<{ name: string }[]>(
    creds, `/accounts/${creds.accountID}/pages/projects/${project}/domains`);
  return result.map((r) => r.name);
}

// --- DNS -------------------------------------------------------------------

export async function listZones(creds: CfCredentials): Promise<{ id: string; name: string }[]> {
  return cfFetch<{ id: string; name: string }[]>(creds, '/zones');
}

export async function createProxiedCNAME(
  creds: CfCredentials, zoneID: string, name: string, content: string,
): Promise<void> {
  await cfFetch(creds, `/zones/${zoneID}/dns_records`, {
    method: 'POST',
    body: JSON.stringify({ type: 'CNAME', name, content, ttl: 1, proxied: true, comment: 'ForgeEdge' }),
  });
}

// --- Status ----------------------------------------------------------------

export async function status(
  creds: CfCredentials, target: DeployTarget, name: string,
): Promise<DeployStatus> {
  const out: DeployStatus = { target, name, exists: false, hostnames: [] };
  try {
    if (target === 'workers') {
      await cfFetch(creds, `/accounts/${creds.accountID}/workers/scripts/${name}`);
      out.exists = true;
      out.hostnames = await workerDomains(creds, name);
    } else {
      const project = await cfFetch<{ subdomain: string; latest_deployment?: { created_on: string } }>(
        creds, `/accounts/${creds.accountID}/pages/projects/${name}`);
      out.exists = true;
      out.hostnames = [project.subdomain, ...(await pagesDomains(creds, name))];
      out.lastDeployed = project.latest_deployment?.created_on;
    }
  } catch (e) {
    out.error = safeError(e);
  }
  return out;
}

// --- Update check ----------------------------------------------------------

export interface UpdateInfo {
  current: string;
  latest: string;
  updateAvailable: boolean;
  releaseURL?: string;
  checkedAt: string;
}

/**
 * Daily update check against GitHub Releases. Deliberately read-only: it reports
 * that a newer release exists and links to it. ForgeEdge NEVER fetches and
 * self-executes a remote script — a Worker that rewrites its own code from the
 * internet is a supply-chain compromise waiting to happen, and the operator
 * loses the ability to see the diff before it runs.
 */
export async function checkForUpdate(repo: string, current: string): Promise<UpdateInfo> {
  const checkedAt = new Date().toISOString();
  try {
    const res = await fetch(`https://api.github.com/repos/${repo}/releases/latest`, {
      headers: { 'User-Agent': 'ForgeEdge', Accept: 'application/vnd.github+json' },
    });
    if (!res.ok) return { current, latest: current, updateAvailable: false, checkedAt };
    const rel = (await res.json()) as { tag_name?: string; html_url?: string };
    const latest = (rel.tag_name ?? '').replace(/^v/, '');
    return {
      current,
      latest: latest || current,
      updateAvailable: !!latest && latest !== current,
      releaseURL: rel.html_url,
      checkedAt,
    };
  } catch {
    return { current, latest: current, updateAvailable: false, checkedAt };
  }
}
