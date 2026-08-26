<script lang="ts">
	import { tr } from '$lib/i18n';
  import { onMount } from 'svelte';
  import { apiFetch, getAuthToken } from '$lib/api';
  import { showToast } from '$lib/components/Toast.svelte';

  interface Deployment {
    id: number;
    name: string;
    origin: string;
    secure_path: string;
    account_id: string;
    last_status?: string;
    last_push_at?: string;
    has_push_token: boolean;
  }
  interface DeployResult {
    deployment: { name: string; origin: string; secure_path: string; panel_url: string; subscription_template: string; doh_url: string };
    id?: number;
    registered: boolean;
  }

  let deployments = $state<Deployment[]>([]);
  let embedded = $state(false);
  let tokenURL = $state('');
  let loading = $state(true);

  // Connect + deploy form. The API token is NEVER persisted server-side — it is
  // used for this deploy/delete only, so it stays in the browser.
  let apiToken = $state('');
  let accountId = $state('');
  let workerName = $state('');
  let proxyIP = $state('');
  let deploying = $state(false);
  let lastResult = $state<DeployResult['deployment'] | null>(null);
  let warpingId = $state<number | null>(null);

  async function load() {
    loading = true;
    try {
      const [deps, info, tok] = await Promise.all([
        apiFetch<Deployment[]>('/admin/edge/deployments'),
        apiFetch<{ embedded: boolean }>('/admin/edge/bundle'),
        apiFetch<{ url: string }>('/admin/edge/token-url'),
      ]);
      deployments = deps ?? [];
      embedded = info.embedded;
      tokenURL = tok.url;
    } catch (e: any) {
      showToast(e?.message || tr('forgeedge.failed_to_load_forgeedge'), 'error');
    } finally {
      loading = false;
    }
  }
  onMount(load);

  function panelUrl(d: Deployment) { return `${d.origin}/${d.secure_path}/panel`; }

  async function deploy() {
    if (!apiToken.trim() || !accountId.trim()) {
      showToast(tr('forgeedge.paste_a_cloudflare_api_token_and'), 'error');
      return;
    }
    deploying = true;
    try {
      const res = await apiFetch<DeployResult>('/admin/edge/deploy', {
        method: 'POST',
        body: JSON.stringify({
          api_token: apiToken.trim(), account_id: accountId.trim(),
          name: workerName.trim() || undefined, proxy_ip: proxyIP.trim() || undefined,
        }),
      });
      lastResult = res.deployment;
      showToast(tr('forgeedge.deployed_name_to_cloudflare', { name: res.deployment.name }), 'success');
      // Push the current feed so the worker serves live configs immediately.
      if (res.id) {
        try { await apiFetch(`/admin/edge/deployments/${res.id}/push`, { method: 'POST' }); } catch (_) {}
      }
      await load();
    } catch (e: any) {
      showToast(e?.message || tr('forgeedge.deploy_failed'), 'error');
    } finally {
      deploying = false;
    }
  }

  async function pushFeed(d: Deployment) {
    try {
      await apiFetch(`/admin/edge/deployments/${d.id}/push`, { method: 'POST' });
      showToast(tr('forgeedge.pushed_the_current_feed_to_name', { name: d.name }), 'success');
      await load();
    } catch (e: any) {
      showToast(e?.message || tr('forgeedge.push_failed'), 'error');
    }
  }

  // One-click free WARP + Amnezia: registers WARP on the deployed worker (via
  // its push token — no worker password needed) and re-pushes the feed so the
  // subscription immediately serves the WireGuard + AmneziaWG nodes.
  async function registerWarp(d: Deployment) {
    warpingId = d.id;
    try {
      const res = await apiFetch<{ count: number }>(`/admin/edge/deployments/${d.id}/warp`, { method: 'POST' });
      showToast(tr('forgeedge.registered_count_warp_account_s_on', { count: res.count, name: d.name }), 'success');
      await load();
    } catch (e: any) {
      showToast(e?.message || tr('forgeedge.warp_registration_failed'), 'error');
    } finally {
      warpingId = null;
    }
  }

  // The .conf is a text attachment, not JSON — fetch it raw with the auth header
  // and save it, so it can be imported straight into the Amnezia / WG app.
  async function downloadConf(d: Deployment, pro: boolean) {
    try {
      const r = await fetch(`/api/admin/edge/deployments/${d.id}/warp.conf${pro ? '?pro=1' : ''}`, {
        headers: { Authorization: `Bearer ${getAuthToken()}` },
      });
      if (!r.ok) {
        let m = `HTTP ${r.status}`;
        try { m = (await r.json()).error || m; } catch (_) {}
        throw new Error(m);
      }
      const text = await r.text();
      const blob = new Blob([text], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = pro ? `${d.name}-warp-amnezia.conf` : `${d.name}-warp.conf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e: any) {
      showToast(e?.message || tr('forgeedge.could_not_fetch_the_conf_register'), 'error');
    }
  }

  async function destroy(d: Deployment) {
    const tok = apiToken.trim();
    if (!tok) { showToast(tr('forgeedge.paste_the_cloudflare_api_token_above'), 'error'); return; }
    if (!confirm(tr('forgeedge.delete_name_every_subscription_url_it', { name: d.name }))) return;
    try {
      await apiFetch(`/admin/edge/deploy/${encodeURIComponent(d.name)}?api_token=${encodeURIComponent(tok)}&account_id=${encodeURIComponent(d.account_id || accountId.trim())}`, { method: 'DELETE' });
      showToast(tr('forgeedge.deleted_name', { name: d.name }), 'success');
      await load();
    } catch (e: any) {
      showToast(e?.message || tr('forgeedge.delete_failed'), 'error');
    }
  }

  function copy(t: string) { navigator.clipboard?.writeText(t); showToast(tr('forgeedge.copied'), 'success'); }
</script>

<div class="edge">
  <div class="head">
    <div>
      <h1>{tr('forgeedge.forgeedge')}</h1>
      <p class="sub">{tr('forgeedge.run_a_cloudflare_worker_that_terminates')} <b>{tr('forgeedge.vless_amp_trojan_over_websocket')}</b> {tr('forgeedge.at_the_edge_and_serves_the')} <b>{tr('forgeedge.same_subscription_your_vps_does')}</b> {tr('forgeedge.so_a_user_s_single_link')} <b>{tr('forgeedge.cloudflare_warp')}</b> + <b>AmneziaWG</b> {tr('forgeedge.dpi_obfuscated_wireguard_to_that_subscription')}</p>
    </div>
    {#if embedded}<span class="pill ok">{tr('forgeedge.worker_bundled')}</span>{:else}<span class="pill warn">{tr('forgeedge.no_bundle')}</span>{/if}
  </div>

  {#if loading}
    <div class="card muted">{tr('forgeedge.loading')}</div>
  {:else}
    <!-- Connect + deploy -->
    <div class="card">
      <h2>{tr('forgeedge.deploy_a_new_edge')}</h2>
      <ol class="steps">
        <li>{tr('forgeedge.create_a_scoped_cloudflare_api_token', {  })}
          {#if tokenURL}<a class="btn sm" href={tokenURL} target="_blank" rel="noopener">{tr('forgeedge.create_token')}</a>{/if}
        </li>
        <li>{tr('forgeedge.find_your')} <b>{tr('forgeedge.account_id')}</b> {tr('forgeedge.on_the_cloudflare_dashboard_sidebar_then')}</li>
      </ol>
      <div class="grid">
        <label>{tr('forgeedge.api_token')}<input type="password" bind:value={apiToken} placeholder={tr('forgeedge.cloudflare_api_token')} autocomplete="off" /></label>
        <label>{tr('forgeedge.account_id')}<input type="text" bind:value={accountId} placeholder={tr('forgeedge.32_char_account_id')} autocomplete="off" /></label>
        <label>{tr('forgeedge.worker_name')} <span class="opt">{tr('forgeedge.optional')}</span><input type="text" bind:value={workerName} placeholder={tr('forgeedge.auto_generated')} /></label>
        <label>{tr('forgeedge.proxy_ip')} <span class="opt">{tr('forgeedge.optional_relay_for_cloudflare_hosted_sites')}</span><input type="text" bind:value={proxyIP} placeholder={tr('forgeedge.host_port')} /></label>
      </div>
      <button class="btn primary" onclick={deploy} disabled={deploying}>{deploying ? tr('forgeedge.deploying') : tr('forgeedge.deploy_to_cloudflare')}</button>
      <p class="note">{tr('forgeedge.the_token_is_used_only_for')}</p>

      {#if lastResult}
        <div class="result">
          <div class="ok-row">{tr('forgeedge.live_at')} <a href={`${lastResult.origin}/${lastResult.secure_path}/panel`} target="_blank" rel="noopener">{lastResult.origin}</a></div>
          <div class="urlrow"><span>{tr('forgeedge.panel')}</span><code>{tr('forgeedge.panel_2', { origin: lastResult.origin, secure_path: lastResult.secure_path })}</code><button class="btn xs" onclick={() => copy(`${lastResult!.origin}/${lastResult!.secure_path}/panel`)}>{tr('forgeedge.copy')}</button></div>
          <div class="urlrow"><span>DoH</span><code>{lastResult.doh_url}</code><button class="btn xs" onclick={() => copy(lastResult!.doh_url)}>{tr('forgeedge.copy')}</button></div>
        </div>
      {/if}
    </div>

    <!-- Deployments -->
    <div class="card">
      <h2>{tr('forgeedge.your_edges')} <span class="count">{deployments.length}</span></h2>
      {#if deployments.length === 0}
        <p class="muted">{tr('forgeedge.no_edges_deployed_yet_deploy_one')}</p>
      {:else}
        {#each deployments as d (d.id)}
          <div class="dep">
            <div class="dep-main">
              <div class="dep-name">{d.name}</div>
              <a class="dep-origin" href={panelUrl(d)} target="_blank" rel="noopener">{d.origin}</a>
              <div class="dep-meta">
                {#if d.last_status}<span class="tag">{d.last_status}</span>{/if}
                {#if d.last_push_at}<span class="muted">{tr('forgeedge.last_push', { p1: new Date(d.last_push_at).toLocaleString() })}</span>{/if}
              </div>
            </div>
            <div class="dep-actions">
              <button class="btn sm warp" onclick={() => registerWarp(d)} disabled={warpingId === d.id} title={tr('forgeedge.register_free_cloudflare_warp_and_add')}>
                {warpingId === d.id ? tr('forgeedge.registering') : tr('forgeedge.warp_amnezia')}
              </button>
              <button class="btn sm" onclick={() => downloadConf(d, true)} title={tr('forgeedge.download_the_amneziawg_conf_for_the')}>{tr('forgeedge.amnezia_conf')}</button>
              <button class="btn sm" onclick={() => downloadConf(d, false)} title={tr('forgeedge.download_the_plain_wireguard_warp_conf')}>{tr('forgeedge.wg_conf')}</button>
              <button class="btn sm" onclick={() => pushFeed(d)}>{tr('forgeedge.push_feed')}</button>
              <a class="btn sm" href={panelUrl(d)} target="_blank" rel="noopener">{tr('forgeedge.open_panel')}</a>
              <button class="btn sm danger" onclick={() => destroy(d)}>{tr('forgeedge.delete')}</button>
            </div>
          </div>
        {/each}
      {/if}
    </div>
  {/if}
</div>

<style>
  .edge { max-width: 860px; margin: 0 auto; }
  .head { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; margin-bottom: 18px; }
  h1 { font-size: 20px; margin: 0 0 4px; }
  .sub { color: var(--muted, #8a97b8); font-size: 13px; line-height: 1.5; margin: 0; max-width: 640px; }
  .pill { font-size: 11px; padding: 4px 10px; border-radius: 999px; white-space: nowrap; }
  .pill.ok { background: rgba(39,209,124,.15); color: #27d17c; }
  .pill.warn { background: rgba(255,170,26,.15); color: #ffaa1a; }
  .card { background: var(--card, #131a2b); border: 1px solid rgba(255,255,255,.07); border-radius: 12px; padding: 18px; margin-bottom: 16px; }
  .card.muted, .muted { color: var(--muted, #8a97b8); }
  h2 { font-size: 15px; margin: 0 0 12px; }
  .count { color: var(--muted, #8a97b8); font-weight: 400; }
  .steps { margin: 0 0 14px; padding-inline-start: 18px; color: var(--muted, #8a97b8); font-size: 13px; line-height: 1.7; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 14px; }
  label { display: flex; flex-direction: column; gap: 5px; font-size: 12px; color: var(--muted, #8a97b8); }
  .opt { color: rgba(255,255,255,.35); }
  input { background: #0d121f; border: 1px solid rgba(255,255,255,.1); border-radius: 8px; padding: 9px 11px; color: #fff; font-size: 13px; }
  input:focus { outline: none; border-color: var(--acc, #ff7a1a); }
  .btn { background: rgba(255,255,255,.08); color: #fff; border: 1px solid rgba(255,255,255,.12); border-radius: 8px; padding: 8px 14px; font-size: 13px; cursor: pointer; text-decoration: none; display: inline-block; }
  .btn:hover { background: rgba(255,255,255,.14); }
  .btn.primary { background: var(--acc, #ff7a1a); border-color: var(--acc, #ff7a1a); color: #000; font-weight: 600; }
  .btn.primary:disabled { opacity: .6; cursor: default; }
  .btn.sm { padding: 6px 11px; font-size: 12px; }
  .btn.xs { padding: 4px 9px; font-size: 11px; }
  .btn.danger { color: #ff6b6b; border-color: rgba(255,107,107,.3); }
  .btn.danger:hover { background: rgba(255,107,107,.15); }
  .btn.warp { color: #27d17c; border-color: rgba(39,209,124,.35); }
  .btn.warp:hover { background: rgba(39,209,124,.15); }
  .btn.warp:disabled { opacity: .6; cursor: default; }
  .note { color: rgba(255,255,255,.35); font-size: 11px; margin: 8px 0 0; }
  .result { margin-top: 14px; padding-top: 14px; border-top: 1px solid rgba(255,255,255,.08); }
  .ok-row { color: #27d17c; font-size: 13px; margin-bottom: 8px; }
  .urlrow { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }
  .urlrow span { color: var(--muted, #8a97b8); font-size: 11px; width: 44px; }
  code { background: #0d121f; border-radius: 6px; padding: 5px 8px; font-size: 11px; color: var(--muted, #8a97b8); word-break: break-all; flex: 1; }
  .dep { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 12px 0; border-top: 1px solid rgba(255,255,255,.06); }
  .dep:first-of-type { border-top: none; }
  .dep-name { font-weight: 600; font-size: 14px; }
  .dep-origin { color: var(--muted, #8a97b8); font-size: 12px; text-decoration: none; }
  .dep-origin:hover { color: var(--acc, #ff7a1a); }
  .dep-meta { display: flex; gap: 10px; align-items: center; margin-top: 4px; font-size: 11px; }
  .tag { background: rgba(255,255,255,.08); border-radius: 5px; padding: 2px 7px; }
  .dep-actions { display: flex; gap: 6px; flex-shrink: 0; }
  @media (max-width: 640px) { .grid { grid-template-columns: 1fr; } .dep { flex-direction: column; align-items: flex-start; } }
</style>
