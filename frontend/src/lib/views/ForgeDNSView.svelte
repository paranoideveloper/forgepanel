<script lang="ts">
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
      showToast(err.message || 'Failed to load DNS state', 'error');
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
      // Backend keys the zone on `zone` (the primary tunnel domain) + `adapter`.
      const created = await apiFetch<DNSZone>('/admin/forgedns/zones', {
        method: 'POST',
        body: JSON.stringify({ zone: newDomain.trim(), adapter: selectedAdapter })
      });
      newDomain = '';
      showToast('DNS Tunnel Zone created & activated', 'success');
      await loadData();
      await showSetup(created);
    } catch (err: any) {
      createErr = err.message || 'Failed to create zone';
    }
  }

  async function showSetup(z: DNSZone) {
    bundleZone = z;
    bundle = null;
    try {
      bundle = await apiFetch<DNSBundle>(`/admin/forgedns/zones/${z.id}/bundle`);
    } catch (err: any) {
      showToast(err.message || 'Failed to load delegation bundle', 'error');
    }
  }

  async function deleteZone(id: number) {
    if (!confirm('Delete this DNS tunnel zone?')) return;
    try {
      await apiFetch(`/admin/forgedns/zones/${id}`, { method: 'DELETE' });
      if (bundleZone?.id === id) { bundleZone = null; bundle = null; }
      showToast('Zone deleted', 'info');
      await loadData();
    } catch (err: any) {
      showToast(err.message || 'Failed to delete zone', 'error');
    }
  }

  async function copyText(text: string, label: string) {
    try {
      await navigator.clipboard.writeText(text);
      showToast(`${label} copied to clipboard`, 'success');
    } catch (_) {
      showToast('Failed to copy', 'error');
    }
  }

  onMount(() => { loadData(); });
</script>

<div class="view-header">
  <h2>ForgeDNS — DNS Tunnels</h2>
  <button class="btn-primary" onclick={loadData}>Refresh</button>
</div>

<div class="card">
  <h3>Create DNS Tunnel Zone</h3>
  <div class="form-row">
    <input type="text" bind:value={newDomain} placeholder="Tunnel domain (e.g. dns.example.com)" data-testid="zone-domain" />
    <select bind:value={selectedAdapter} data-testid="adapter-select">
      {#each adapters as a}
        <option value={a.id}>{a.name}</option>
      {/each}
    </select>
    <button class="btn-primary" onclick={createZone} data-testid="create-zone">Create &amp; Activate</button>
  </div>
  {#if createErr}<p class="err-text">{createErr}</p>{/if}
  {#if selectedAdapter}
    <p class="muted" style="margin-top:8px;font-size:13px">
      {adapters.find((a) => a.id === selectedAdapter)?.description || 'Pick a wire format adapter and enter your delegated domain.'}
      ForgePanel will automatically manage authoritative DNS listeners.
    </p>
  {/if}
</div>

<div class="card table-card">
  {#if loading}
    <p class="muted">Loading DNS zones...</p>
  {:else if zones.length === 0}
    <p class="muted" data-testid="no-zones">No DNS tunnel zones yet. Create one above to get delegation records and a client config.</p>
  {:else}
    <table>
      <thead>
        <tr>
          <th>Zone Domain</th>
          <th>Adapter</th>
          <th>Status</th>
          <th>Listener</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {#each zones as z}
          <tr data-testid="zone-row">
            <td><strong>{z.zone}</strong></td>
            <td><code>{z.adapter}</code></td>
            <td>
              <span class="badge {z.enabled ? 'badge-ok' : 'badge-err'}">
                {z.enabled ? 'Active' : 'Stopped'}
              </span>
            </td>
            <td><code>{z.bind_host || '0.0.0.0'}:{z.bind_port || 53}</code></td>
            <td class="action-cell">
              <button class="btn-sm" onclick={() => showSetup(z)} data-testid="setup-info">Setup Info</button>
              <button class="btn-sm danger" onclick={() => deleteZone(z.id)} data-testid="delete-zone">Delete</button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

{#if bundleZone}
  <div class="card" data-testid="setup-panel">
    <h3>Delegation &amp; Setup — {bundleZone.zone}</h3>
    {#if !bundle}
      <p class="muted">Loading delegation records…</p>
    {:else}
      <p class="muted" style="font-size:13px">
        Add these records at your domain registrar to delegate DNS traffic to this server:
      </p>
      {#if bundle.ns_records && bundle.ns_records.length > 0}
        <table>
          <thead>
            <tr><th>Type</th><th>Name</th><th>Value</th></tr>
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
      {#if bundle.socks5}
        <p style="margin-top:14px"><span class="muted">Client SOCKS5:</span> <code>{bundle.socks5}</code></p>
      {/if}
      {#if bundle.client_config_toml}
        <div style="margin-top:16px">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
            <span class="muted">Client config (the credential — keep it secret):</span>
            <button class="btn-sm" onclick={() => copyText(bundle!.client_config_toml, 'Client config')} data-testid="copy-config">Copy config</button>
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
  .card { background: #141A24; border: 1px solid rgba(255,255,255,0.08); border-radius: 14px; padding: 20px; margin-bottom: 20px; }
  .card h3 { margin: 0 0 16px; font-size: 14px; text-transform: uppercase; color: rgba(255,255,255,0.7); }
  .form-row { display: flex; gap: 12px; flex-wrap: wrap; align-items: center; }
  .form-row input { flex: 1; min-width: 200px; }
  .form-row select { min-width: 160px; }
  input, select { background: #0F1420; border: 1px solid rgba(255,255,255,0.12); color: #fff; padding: 10px; border-radius: 8px; font: inherit; }
  .btn-primary { background: #FF7A1A; color: #1a1204; border: none; font-weight: 700; padding: 10px 16px; border-radius: 8px; cursor: pointer; }
  .btn-sm { background: #1A2230; color: #fff; border: 1px solid rgba(255,255,255,0.1); padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; }
  .btn-sm.danger { color: #FF4D4D; border-color: rgba(255,77,77,0.3); }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 12px; border-bottom: 1px solid rgba(255,255,255,0.08); font-size: 14px; word-break: break-all; }
  th { color: rgba(255,255,255,0.6); font-weight: 600; }
  .badge { padding: 4px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }
  .badge-ok { background: rgba(39,209,124,0.15); color: #27D17C; }
  .badge-err { background: rgba(255,77,77,0.15); color: #FF4D4D; }
  .action-cell { display: flex; gap: 6px; }
  .err-text { color: #FF4D4D; font-size: 13px; margin-top: 8px; }
  .muted { color: rgba(255,255,255,0.6); }
  .warn-box { margin-top: 12px; padding: 10px 12px; border-radius: 8px; font-size: 13px; background: rgba(255,176,32,0.1); border: 1px solid rgba(255,176,32,0.3); color: #FFC24B; }
  .config { margin: 0; padding: 12px; background: #0F1420; border: 1px solid rgba(255,255,255,0.12); border-radius: 8px; font-size: 12px; color: #cfe; overflow-x: auto; white-space: pre; }
  .steps { margin: 16px 0 0; padding-left: 20px; font-size: 13px; color: rgba(255,255,255,0.75); }
  .steps li { margin-bottom: 6px; }
</style>
