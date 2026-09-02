<script lang="ts">
	import { tr } from '$lib/i18n';
  import { onMount } from 'svelte';
  import { apiFetch } from '$lib/api';
  import type { DNSZone, DNSAdapter, DNSBundle } from '$lib/types';
  import { showToast } from '$lib/components/Toast.svelte';

  let adapters = $state<DNSAdapter[]>([]);
  let zones = $state<DNSZone[]>([]);
  let bundle = $state<DNSBundle | null>(null);
  let bundleZone = $state<DNSZone | null>(null);
  let loading = $state(true);

  let newDomain = $state('');
  let extraDomains = $state('');
  let selectedAdapter = $state('');
  let createErr = $state('');

  async function loadData() {
    loading = true;
    try {
      adapters = await apiFetch<DNSAdapter[]>('/admin/forgedns/adapters');
      if (adapters.length > 0 && !selectedAdapter) {
        selectedAdapter = adapters[0].id;
      }
      zones = await apiFetch<DNSZone[]>('/admin/forgedns/zones');
    } catch (err: any) {
      showToast(err.message || tr('forgedns.failed_to_load_dns_state'), 'error');
    } finally {
      loading = false;
    }
  }

  async function createZone() {
    createErr = '';
    if (!newDomain.trim()) {
      createErr = 'Tunnel domain is required';
      return;
    }
    try {
      // Backend keys the zone on `zone` (the primary tunnel domain) + `adapter`,
      // and carries any additional tunnel domains in `domains` — CottenDNS/Master/
      // StormDNS all handle a DOMAIN array, every one delegated to this server.
      const domains = extraDomains.split(/[\s,]+/).map((d) => d.trim()).filter(Boolean);
      const created = await apiFetch<DNSZone>('/admin/forgedns/zones', {
        method: 'POST',
        body: JSON.stringify({ zone: newDomain.trim(), adapter: selectedAdapter, domains })
      });
      newDomain = '';
      extraDomains = '';
      showToast(tr('forgedns.dns_tunnel_zone_created_activated'), 'success');
      await loadData();
      await showSetup(created);
    } catch (err: any) {
      createErr = err.message || tr('forgedns.failed_to_create_zone');
    }
  }

  async function showSetup(z: DNSZone) {
    bundleZone = z;
    bundle = null;
    try {
      bundle = await apiFetch<DNSBundle>(`/admin/forgedns/zones/${z.id}/bundle`);
    } catch (err: any) {
      showToast(err.message || tr('forgedns.failed_to_load_delegation_bundle'), 'error');
    }
  }

  async function deleteZone(id: number) {
    if (!confirm(tr('forgedns.delete_this_dns_tunnel_zone'))) return;
    try {
      await apiFetch(`/admin/forgedns/zones/${id}`, { method: 'DELETE' });
      if (bundleZone?.id === id) { bundleZone = null; bundle = null; }
      showToast(tr('forgedns.zone_deleted'), 'info');
      await loadData();
    } catch (err: any) {
      showToast(err.message || tr('forgedns.failed_to_delete_zone'), 'error');
    }
  }

  async function copyText(text: string, label: string) {
    try {
      await navigator.clipboard.writeText(text);
      showToast(tr('forgedns.label_copied_to_clipboard', { label }), 'success');
    } catch (_) {
      showToast(tr('forgedns.failed_to_copy'), 'error');
    }
  }

  onMount(() => { loadData(); });
</script>

<div class="view-header">
  <h2>{tr('forgedns.forgedns_dns_tunnels')}</h2>
  <button class="btn-primary" onclick={loadData}>{tr('forgedns.refresh')}</button>
</div>

<div class="card">
  <h3>{tr('forgedns.create_dns_tunnel_zone')}</h3>
  <div class="form-row">
    <input type="text" bind:value={newDomain} placeholder={tr('forgedns.tunnel_domain_e_g_dns_example')} data-testid="zone-domain" />
    <select bind:value={selectedAdapter} data-testid="adapter-select">
      {#each adapters as a}
        <option value={a.id}>{a.name}</option>
      {/each}
    </select>
    <button class="btn-primary" onclick={createZone} data-testid="create-zone">{tr('forgedns.create_amp_activate')}</button>
  </div>
  <div class="form-row" style="margin-top:10px">
    <input type="text" bind:value={extraDomains} placeholder={tr('forgedns.additional_tunnel_domains_optional_comma_separated')} data-testid="zone-extra-domains" style="flex:1" />
  </div>
  {#if createErr}<p class="err-text">{createErr}</p>{/if}
  {#if selectedAdapter}
    <p class="muted" style="margin-top:8px;font-size:13px">
      {tr('forgedns.forgepanel_will_automatically_manage_authoritative_dns', { p1: adapters.find((a) => a.id === selectedAdapter)?.description || tr('forgedns.pick_a_wire_format_adapter_and') })}
    </p>
  {/if}
</div>

<div class="card table-card">
  {#if loading}
    <p class="muted">{tr('forgedns.loading_dns_zones')}</p>
  {:else if zones.length === 0}
    <p class="muted" data-testid="no-zones">{tr('forgedns.no_dns_tunnel_zones_yet_create')}</p>
  {:else}
    <table>
      <thead>
        <tr>
          <th>{tr('forgedns.zone_domain')}</th>
          <th>{tr('forgedns.adapter')}</th>
          <th>{tr('forgedns.status')}</th>
          <th>{tr('forgedns.listener')}</th>
          <th>{tr('forgedns.actions')}</th>
        </tr>
      </thead>
      <tbody>
        {#each zones as z}
          <tr data-testid="zone-row">
            <td><strong>{z.zone}</strong></td>
            <td><code>{z.adapter}</code></td>
            <td>
              <span class="badge {z.enabled ? 'badge-ok' : 'badge-err'}">
                {z.enabled ? tr('forgedns.active') : tr('forgedns.stopped')}
              </span>
            </td>
            <td><code>{z.bind_host || '0.0.0.0'}:{z.bind_port || 53}</code></td>
            <td class="action-cell">
              <button class="btn-sm" onclick={() => showSetup(z)} data-testid="setup-info">{tr('forgedns.setup_info')}</button>
              <button class="btn-sm danger" onclick={() => deleteZone(z.id)} data-testid="delete-zone">{tr('forgedns.delete')}</button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

{#if bundleZone}
  <div class="card" data-testid="setup-panel">
    <h3>{tr('forgedns.delegation_amp_setup', { zone: bundleZone.zone })}</h3>
    {#if !bundle}
      <p class="muted">{tr('forgedns.loading_delegation_records')}</p>
    {:else}
      <p class="muted" style="font-size:13px">
        {tr('forgedns.add_these_records_at_your_domain')}
      </p>
      {#if bundle.ns_records && bundle.ns_records.length > 0}
        <table>
          <thead>
            <tr><th>{tr('forgedns.type')}</th><th>{tr('forgedns.name')}</th><th>{tr('forgedns.value')}</th></tr>
          </thead>
          <tbody>
            {#each bundle.ns_records as r}
              <tr data-testid="ns-record">
                <td><code>{r.type}</code></td>
                <td><code>{r.name}</code></td>
                <td><code>{r.value}</code></td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
      {#if bundle.cloudflare_warning}
        <div class="warn-box">⚠️ {bundle.cloudflare_warning}</div>
      {/if}
      <div class="warn-box">{tr('forgedns.the_authoritative_listener_runs_on')} <code>0.0.0.0:53</code>{tr('forgedns.port')} <strong>{tr('forgedns.53_udp')}</strong> {tr('forgedns.must_be_open_on_this_server')} <code>{tr('forgedns.53_53_udp')}</code> {tr('forgedns.in_your_compose_ports_or_delegated')}</div>
      {#if bundle.socks5}
        <p style="margin-top:14px"><span class="muted">{tr('forgedns.client_socks5')}</span> <code>{bundle.socks5}</code></p>
      {/if}
      {#if bundle.client_config_toml}
        <div style="margin-top:16px">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
            <span class="muted">{tr('forgedns.client_config_the_credential_keep_it')}</span>
            <button class="btn-sm" onclick={() => copyText(bundle!.client_config_toml, tr('forgedns.client_config'))} data-testid="copy-config">{tr('forgedns.copy_config')}</button>
          </div>
          <pre class="config" data-testid="client-config">{bundle.client_config_toml}</pre>
        </div>
      {/if}
      {#if bundle.steps && bundle.steps.length > 0}
        <ol class="steps">
          {#each bundle.steps as step}<li>{step}</li>{/each}
        </ol>
      {/if}
    {/if}
  </div>
{/if}

<style>
  .view-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
  .view-header h2 { margin: 0; font-size: 20px; font-weight: 650; }
  .card { background: var(--card); border: 1px solid var(--ln-3); border-radius: 14px; padding: 20px; margin-bottom: 20px; }
  .card h3 { margin: 0 0 16px; font-size: 14px; text-transform: uppercase; color: var(--t-3); }
  .form-row { display: flex; gap: 12px; flex-wrap: wrap; align-items: center; }
  .form-row input { flex: 1; min-width: 200px; }
  .form-row select { min-width: 160px; }
  input, select { background: var(--bg); border: 1px solid var(--ln-5); color: var(--fg); padding: 10px; border-radius: 8px; font: inherit; }
  .btn-primary { background: var(--acc); color: var(--acc-soft); border: none; font-weight: 700; padding: 10px 16px; border-radius: 8px; cursor: pointer; }
  .btn-sm { background: var(--raised); color: var(--fg); border: 1px solid var(--ln-4); padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; }
  .btn-sm.danger { color: var(--bad); border-color: rgba(255,77,77,0.3); }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: start; padding: 12px; border-bottom: 1px solid var(--ln-3); font-size: 14px; word-break: break-all; }
  th { color: var(--t-5); font-weight: 600; }
  .badge { padding: 4px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }
  .badge-ok { background: rgba(39,209,124,0.15); color: var(--ok); }
  .badge-err { background: rgba(255,77,77,0.15); color: var(--bad); }
  .action-cell { display: flex; gap: 6px; }
  .err-text { color: var(--bad); font-size: 13px; margin-top: 8px; }
  .muted { color: var(--t-5); }
  .warn-box { margin-top: 12px; padding: 10px 12px; border-radius: 8px; font-size: 13px; background: rgba(255,176,32,0.1); border: 1px solid rgba(255,176,32,0.3); color: var(--warn-2); }
  .config { margin: 0; padding: 12px; background: var(--bg); border: 1px solid var(--ln-5); border-radius: 8px; font-size: 12px; color: #cfe; overflow-x: auto; white-space: pre; }
  .steps { margin: 16px 0 0; padding-inline-start: 20px; font-size: 13px; color: var(--t-2); }
  .steps li { margin-bottom: 6px; }
</style>
