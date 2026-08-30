<script lang="ts">
	import { tr } from '$lib/i18n';
  import { onMount } from 'svelte';
  import { apiFetch, getAuthToken } from '$lib/api';
  import EdgeConfigEditor from '$lib/components/EdgeConfigEditor.svelte';
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
  let configId = $state<number | null>(null);
  let embedded = $state(false);
  let tokenURL = $state('');
  let loading = $state(true);

  // Connect + deploy form. The API token is NEVER persisted server-side — it is
  // used for this deploy/delete only, so it stays in the browser.
  let apiToken = $state('');
  let accountId = $state('');
  let workerName = $state('');
  let proxyIP = $state('');
  // `force` is the one deploy field the API accepted that the form never sent.
  // Without it a name collision came back 409 "a Worker named X already exists"
  // and the operator had no way forward: no control set force, so redeploying
  // over their OWN worker was impossible from the panel. It is deliberately not
  // the default — silently overwriting somebody else's worker is worse than the
  // 409.
  let force = $state(false);
  // Binds this account's Cloudflare credential into the worker, which is the
  // only thing that lights up the worker's own Deployment panel. Opt-in: a
  // token in a binding is readable by anyone who can deploy to the account.
  let selfManage = $state(false);
  // The message from a 409, kept so the retry offer can be shown next to the
  // form rather than living only in a toast that has already faded.
  let conflict = $state('');
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

  // `overwrite` defaults to the checkbox, and the retry offered after a 409
  // passes true explicitly. It must be called as deploy(), never bound straight
  // to onclick: a handler receives the MouseEvent as its first argument, and a
  // truthy event would force every deploy.
  async function deploy(overwrite: boolean = force) {
    if (!apiToken.trim() || !accountId.trim()) {
      showToast(tr('forgeedge.paste_a_cloudflare_api_token_and'), 'error');
      return;
    }
    deploying = true;
    conflict = '';
    try {
      const res = await apiFetch<DeployResult>('/admin/edge/deploy', {
        method: 'POST',
        body: JSON.stringify({
          api_token: apiToken.trim(), account_id: accountId.trim(),
          name: workerName.trim() || undefined, proxy_ip: proxyIP.trim() || undefined,
          force: overwrite, self_manage: selfManage,
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
      // 409 is the name collision, and the only failure the operator can clear
      // from here. Offer the overwrite instead of leaving them at a dead end.
      if (e?.status === 409) conflict = e?.message || tr('forgeedge.deploy_failed');
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
      <label class="check"><input type="checkbox" data-testid="edge-force" bind:checked={force} /> {tr('forgeedge.overwrite_an_existing_worker')} <span class="opt">{tr('forgeedge.only_needed_when_the_name_is')}</span></label>
      <label class="check"><input type="checkbox" data-testid="edge-self-manage" bind:checked={selfManage} /> {tr('forgeedge.let_this_worker_manage_itself')} <span class="opt">{tr('forgeedge.binds_your_api_token_into_the')}</span></label>
      <button class="btn primary" data-testid="edge-deploy" onclick={() => deploy()} disabled={deploying}>{deploying ? tr('forgeedge.deploying') : tr('forgeedge.deploy_to_cloudflare')}</button>
      <p class="note">{tr('forgeedge.the_token_is_used_only_for')}</p>

      {#if conflict}
        <div class="conflict">
          <div>{conflict}</div>
          <button class="btn sm" data-testid="edge-force-retry" onclick={() => deploy(true)} disabled={deploying}>{tr('forgeedge.overwrite_and_redeploy')}</button>
        </div>
      {/if}

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
              <button class="btn sm" onclick={() => (configId = configId === d.id ? null : d.id)}
                title={tr('forgeedge.edit_every_field_of_this_workers')}>{tr('forgeedge.configure')}</button>
              <button class="btn sm" onclick={() => pushFeed(d)}>{tr('forgeedge.push_feed')}</button>
              <a class="btn sm" href={panelUrl(d)} target="_blank" rel="noopener">{tr('forgeedge.open_panel')}</a>
              <button class="btn sm danger" onclick={() => destroy(d)}>{tr('forgeedge.delete')}</button>
            </div>
          </div>
          {#if configId === d.id}
            {#key d.id}
              <EdgeConfigEditor deploymentId={d.id} onClose={() => (configId = null)} />
            {/key}
          {/if}
        {/each}
      {/if}
    </div>
  {/if}
</div>

<style>
  .edge { max-width: 860px; margin: 0 auto; }
  .head { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; margin-bottom: 18px; }
  h1 { font-size: 20px; margin: 0 0 4px; }
  .sub { color: var(--muted, var(--mut)); font-size: 13px; line-height: 1.5; margin: 0; max-width: 640px; }
  .pill { font-size: 11px; padding: 4px 10px; border-radius: 999px; white-space: nowrap; }
  .pill.ok { background: rgba(39,209,124,.15); color: var(--ok); }
  .pill.warn { background: rgba(255,170,26,.15); color: var(--warn-2); }
  .card { background: var(--card); border: 1px solid var(--ln-3); border-radius: 12px; padding: 18px; margin-bottom: 16px; }
  .card.muted, .muted { color: var(--muted, var(--mut)); }
  h2 { font-size: 15px; margin: 0 0 12px; }
  .count { color: var(--muted, var(--mut)); font-weight: 400; }
  .steps { margin: 0 0 14px; padding-inline-start: 18px; color: var(--muted, var(--mut)); font-size: 13px; line-height: 1.7; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 14px; }
  label { display: flex; flex-direction: column; gap: 5px; font-size: 12px; color: var(--muted, var(--mut)); }
  .opt { color: var(--t-8); }
  input { background: var(--card-deep); border: 1px solid var(--ln-4); border-radius: 8px; padding: 9px 11px; color: var(--fg); font-size: 13px; }
  input:focus { outline: none; border-color: var(--acc, var(--acc)); }
  .btn { background: var(--ln-3); color: var(--fg); border: 1px solid var(--ln-4); border-radius: 8px; padding: 8px 14px; font-size: 13px; cursor: pointer; text-decoration: none; display: inline-block; }
  .btn:hover { background: var(--ln-5); }
  .btn.primary { background: var(--acc, var(--acc)); border-color: var(--acc, var(--acc)); color: #000; font-weight: 600; }
  .btn.primary:disabled { opacity: .6; cursor: default; }
  .btn.sm { padding: 6px 11px; font-size: 12px; }
  .btn.xs { padding: 4px 9px; font-size: 11px; }
  .btn.danger { color: var(--bad-3); border-color: rgba(255,107,107,.3); }
  .btn.danger:hover { background: rgba(255,107,107,.15); }
  .btn.warp { color: var(--ok); border-color: rgba(39,209,124,.35); }
  .btn.warp:hover { background: rgba(39,209,124,.15); }
  .btn.warp:disabled { opacity: .6; cursor: default; }
  .note { color: var(--t-8); font-size: 11px; margin: 8px 0 0; }
  .check { flex-direction: row; align-items: center; gap: 7px; margin-bottom: 12px; font-size: 12px; }
  .check input { width: auto; }
  .conflict { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-top: 12px; padding: 10px 12px; font-size: 12px; color: var(--warn-2); background: rgba(255,170,26,.1); border: 1px solid rgba(255,170,26,.3); border-radius: 8px; }
  .result { margin-top: 14px; padding-top: 14px; border-top: 1px solid var(--ln-3); }
  .ok-row { color: var(--ok); font-size: 13px; margin-bottom: 8px; }
  .urlrow { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }
  .urlrow span { color: var(--muted, var(--mut)); font-size: 11px; width: 44px; }
  code { background: var(--card-deep); border-radius: 6px; padding: 5px 8px; font-size: 11px; color: var(--muted, var(--mut)); word-break: break-all; flex: 1; }
  .dep { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 12px 0; border-top: 1px solid var(--ln-2); }
  .dep:first-of-type { border-top: none; }
  .dep-name { font-weight: 600; font-size: 14px; }
  .dep-origin { color: var(--muted, var(--mut)); font-size: 12px; text-decoration: none; }
  .dep-origin:hover { color: var(--acc, var(--acc)); }
  .dep-meta { display: flex; gap: 10px; align-items: center; margin-top: 4px; font-size: 11px; }
  .tag { background: var(--ln-3); border-radius: 5px; padding: 2px 7px; }
  .dep-actions { display: flex; gap: 6px; flex-shrink: 0; }
  @media (max-width: 640px) { .grid { grid-template-columns: 1fr; } .dep { flex-direction: column; align-items: flex-start; } }
</style>
