<script lang="ts">
  import { onMount } from 'svelte';
  import { apiFetch } from '$lib/api';
  import type { DNSZone, DNSAdapter } from '$lib/types';
  import { showToast } from '$lib/components/Toast.svelte';

  let adapters = $state<DNSAdapter[]>([]);
  let zones = $state<DNSZone[]>([]);
  let selectedZone = $state<DNSZone | null>(null);
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
      const newZone = await apiFetch<DNSZone>('/admin/forgedns/zones', {
        method: 'POST',
        body: JSON.stringify({ domain: newDomain.trim(), adapter: selectedAdapter })
      });
      newDomain = '';
      selectedZone = newZone;
      showToast('DNS Tunnel Zone created & activated', 'success');
      await loadData();
    } catch (err: any) {
      createErr = err.message || 'Failed to create zone';
    }
  }

  async function deleteZone(id: number) {
    if (!confirm('Delete this DNS tunnel zone?')) return;
    try {
      await apiFetch(`/admin/forgedns/zones/${id}`, { method: 'DELETE' });
      if (selectedZone?.id === id) selectedZone = null;
      showToast('Zone deleted', 'info');
      await loadData();
    } catch (err: any) {
      showToast(err.message || 'Failed to delete zone', 'error');
    }
  }

  async function copyClientUri(uri: string) {
    try {
      await navigator.clipboard.writeText(uri);
      showToast('Client URI copied to clipboard', 'success');
    } catch (_) {
      showToast('Failed to copy URI', 'error');
    }
  }

  onMount(() => {
    loadData();
  });
</script>

<div class="view-header">
  <h2>ForgeDNS — DNS Tunnels</h2>
  <button class="btn-primary" onclick={loadData}>Refresh</button>
</div>

<div class="card">
  <h3>Create DNS Tunnel Zone</h3>
  <div class="form-row">
    <input type="text" bind:value={newDomain} placeholder="Tunnel domain (e.g. dns.example.com)" />
    <select bind:value={selectedAdapter}>
      {#each adapters as a}
        <option value={a.id}>{a.name}</option>
      {/each}
    </select>
    <button class="btn-primary" onclick={createZone}>Create &amp; Activate</button>
  </div>
  {#if createErr}<p class="err-text">{createErr}</p>{/if}
  <p class="muted" style="margin-top:8px;font-size:13px">
    Pick a wire format adapter and enter your delegated domain. ForgePanel will automatically manage authoritative DNS listeners.
  </p>
</div>

<div class="card table-card">
  {#if loading}
    <p class="muted">Loading DNS zones...</p>
  {:else}
    <table>
      <thead>
        <tr>
          <th>Zone Domain</th>
          <th>Adapter</th>
          <th>Status</th>
          <th>Active Sessions</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {#each zones as z}
          <tr>
            <td><strong>{z.domain}</strong></td>
            <td><code>{z.adapter}</code></td>
            <td>
              <span class="badge {z.active ? 'badge-ok' : 'badge-err'}">
                {z.active ? 'Active' : 'Stopped'}
              </span>
            </td>
            <td>{z.sessions || 0}</td>
            <td class="action-cell">
              <button class="btn-sm" onclick={() => selectedZone = z}>Setup Info</button>
              <button class="btn-sm danger" onclick={() => deleteZone(z.id)}>Delete</button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

{#if selectedZone}
  <div class="card">
    <h3>Delegation &amp; Setup — {selectedZone.domain}</h3>
    <p class="muted" style="font-size:13px">
      Add these NS records at your domain registrar to delegate DNS traffic to this server:
    </p>
    {#if selectedZone.ns_records && selectedZone.ns_records.length > 0}
      <table>
        <thead>
          <tr><th>Host</th><th>Target</th></tr>
        </thead>
        <tbody>
          {#each selectedZone.ns_records as ns}
            <tr>
              <td><code>{ns.host}</code></td>
              <td><code>{ns.target}</code></td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
    {#if selectedZone.client_uri}
      <div style="margin-top:16px">
        <span class="muted">Client URI:</span> <code>{selectedZone.client_uri}</code>
        <button class="btn-sm" style="margin-left:8px" onclick={() => copyClientUri(selectedZone!.client_uri)}>Copy URI</button>
      </div>
    {/if}
  </div>
{/if}

<style>
  .view-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
  .view-header h2 { margin: 0; font-size: 20px; font-weight: 650; }
  .card { background: #141A24; border: 1px solid rgba(255,255,255,0.08); border-radius: 14px; padding: 20px; margin-bottom: 20px; }
  .card h3 { margin: 0 0 16px; font-size: 14px; text-transform: uppercase; color: rgba(255,255,255,0.7); }
  .form-row { display: flex; gap: 12px; }
  .form-row input { flex: 1; }
  input, select { background: #0F1420; border: 1px solid rgba(255,255,255,0.12); color: #fff; padding: 10px; border-radius: 8px; font: inherit; }
  .btn-primary { background: #FF7A1A; color: #1a1204; border: none; font-weight: 700; padding: 10px 16px; border-radius: 8px; cursor: pointer; }
  .btn-sm { background: #1A2230; color: #fff; border: 1px solid rgba(255,255,255,0.1); padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; }
  .btn-sm.danger { color: #FF4D4D; border-color: rgba(255,77,77,0.3); }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 12px; border-bottom: 1px solid rgba(255,255,255,0.08); font-size: 14px; }
  th { color: rgba(255,255,255,0.6); font-weight: 600; }
  .badge { padding: 4px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }
  .badge-ok { background: rgba(39,209,124,0.15); color: #27D17C; }
  .badge-err { background: rgba(255,77,77,0.15); color: #FF4D4D; }
  .action-cell { display: flex; gap: 6px; }
  .err-text { color: #FF4D4D; font-size: 13px; margin-top: 8px; }
  .muted { color: rgba(255,255,255,0.6); }
</style>
