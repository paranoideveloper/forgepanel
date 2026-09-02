/**
 * Cloudflare API operations the panel exposes: reporting where this Worker (or
 * Pages project) is deployed and whether a newer release exists. Read-only, on
 * purpose — every write stays on the panel host, where `forgectl edge` and the
 * panel's own deploy routes use a token for one invocation and never store it.
 *
 * CREDENTIAL POLICY. There are two ways to authorise a deploy, and they are NOT
 * equivalent:
 *
 *   OAuth (preferred) — `forgectl edge deploy` runs a PKCE flow against
 *     dash.cloudflare.com and holds the resulting token on the operator's own
 *     machine. Nothing is ever written into the Worker. This is the default and
 *     the only flow that needs no long-lived secret anywhere.
 *
 *   Self-manage — `--self-manage` (or the panel's own checkbox) binds the
 *     account credential into the Worker as `CF_API_TOKEN` + `CF_ACCOUNT_ID`,
 *     which is what the functions below read. A token stored in a Worker binding
 *     is readable by anyone who can deploy to that account, so it is opt-in, off
 *     by default, and both call sites say what it costs.
 *
 * Without the binding the panel still works completely; only the Deployment
 * section is blank, and it reports exactly why.
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

export async function workerDomains(creds: CfCredentials, name: string): Promise<string[]> {
  const result = await cfFetch<{ hostname: string }[]>(
    creds, `/accounts/${creds.accountID}/workers/domains?service=${encodeURIComponent(name)}`);
  return result.map((r) => r.hostname);
}

// --- Pages -----------------------------------------------------------------

export async function pagesDomains(creds: CfCredentials, project: string): Promise<string[]> {
  const result = await cfFetch<{ name: string }[]>(
    creds, `/accounts/${creds.accountID}/pages/projects/${project}/domains`);
  return result.map((r) => r.name);
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
