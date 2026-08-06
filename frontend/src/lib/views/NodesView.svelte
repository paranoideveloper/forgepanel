<script lang="ts">
  import { onMount } from 'svelte';
  import { apiFetch } from '$lib/api';
  import type { Node } from '$lib/types';
  import Modal from '$lib/components/Modal.svelte';
  import { showToast } from '$lib/components/Toast.svelte';

  let nodes = $state<Node[]>([]);
  let loading = $state(true);

  let newName = $state('');
  let newAddress = $state('');
  let createErr = $state('');

  let scriptModalOpen = $state(false);
  let installScript = $state('');

  async function loadNodes() {
    loading = true;
    try {
      nodes = await apiFetch<Node[]>('/admin/nodes');
    } catch (err: any) {
      showToast(err.message || 'Failed to load nodes', 'error');
    } finally {
      loading = false;
    }
  }

  async function registerNode() {
    createErr = '';
    if (!newName.trim() || !newAddress.trim()) {
      createErr = 'Both Name and Address are required';
      return;
    }
    try {
      await apiFetch('/admin/nodes', {
        method: 'POST',
        body: JSON.stringify({ name: newName.trim(), address: newAddress.trim() })
      });
      newName = '';
      newAddress = '';
      showToast('Node registered successfully', 'success');
      await loadNodes();
    } catch (err: any) {
      createErr = err.message || 'Failed to register node';
    }
  }

  async function deleteNode(id: number) {
    if (!confirm('Remove this node from the cluster?')) return;
    try {
      await apiFetch(`/admin/nodes/${id}`, { method: 'DELETE' });
      showToast('Node deleted', 'info');
      await loadNodes();
    } catch (err: any) {
      showToast(err.message || 'Failed to delete node', 'error');
    }
  }

  function showInstallModal() {
    const origin = window.location.origin;
    installScript = `curl -fsSL ${origin}/api/node/install.sh | PANEL="${origin}" TOKEN="YOUR_ENROLL_TOKEN" bash`;
    scriptModalOpen = true;
  }

  async function copyScript() {
    try {
      await navigator.clipboard.writeText(installScript);
      showToast('Install script copied', 'success');
    } catch (_) {
      showToast('Failed to copy script', 'error');
    }
  }

  onMount(() => {
    loadNodes();
  });
</script>

<div class="view-header">
  <h2>Node Cluster & Daemons</h2>
  <div class="actions">
    <button class="btn-secondary" onclick={showInstallModal}>Install Agent Script</button>
    <button class="btn-primary" onclick={loadNodes}>Refresh</button>
  </div>
</div>

<div class="card">
  <h3>Register Remote Node Agent</h3>
  <div class="form-grid">
    <input type="text" bind:value={newName} placeholder="Node Name (e.g. EU-West-1)" />
    <input type="text" bind:value={newAddress} placeholder="Public IP or Domain" />
    <button class="btn-primary" onclick={registerNode}>Register Node</button>
  </div>
  {#if createErr}<p class="err-text">{createErr}</p>{/if}
</div>

<div class="card table-card">
  {#if loading}
    <p class="muted">Loading node cluster...</p>
  {:else}
    <table>
      <thead>
        <tr>
          <th>Node Name</th>
          <th>Address</th>
          <th>CPU</th>
          <th>Memory</th>
          <th>Status</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {#each nodes as n}
          <tr>
            <td><strong>{n.name}</strong></td>
            <td><code>{n.address}</code></td>
            <td>{n.cpu || 0}%</td>
            <td>{n.mem_mb || 0} MB</td>
            <td>
              <span class="badge {n.healthy ? 'badge-ok' : 'badge-err'}">
                {n.healthy ? 'Online' : 'Stale'}
              </span>
            </td>
            <td>
              <button class="btn-sm danger" onclick={() => deleteNode(n.id)}>Remove</button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

<Modal title="Deploy Node Agent (forgenode)" isOpen={scriptModalOpen} onClose={() => scriptModalOpen = false}>
  <p class="muted">Run this command on your remote server to automatically install and launch <code>forgenode</code>:</p>
  <pre><code>{installScript}</code></pre>
  <button class="btn-primary" onclick={copyScript}>Copy Command</button>
</Modal>

<style>
  .view-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
  .view-header h2 { margin: 0; font-size: 20px; font-weight: 650; }
  .actions { display: flex; gap: 10px; }
  .card { background: #141A24; border: 1px solid rgba(255,255,255,0.08); border-radius: 14px; padding: 20px; margin-bottom: 20px; }
  .card h3 { margin: 0 0 16px; font-size: 14px; text-transform: uppercase; color: rgba(255,255,255,0.7); }
  .form-grid { display: grid; grid-template-columns: 1fr 1fr auto; gap: 12px; }
  input { background: #0F1420; border: 1px solid rgba(255,255,255,0.12); color: #fff; padding: 10px; border-radius: 8px; font: inherit; }
  .btn-primary { background: #FF7A1A; color: #1a1204; border: none; font-weight: 700; padding: 10px 16px; border-radius: 8px; cursor: pointer; }
  .btn-secondary { background: #1A2230; color: #fff; border: 1px solid rgba(255,255,255,0.1); padding: 10px 16px; border-radius: 8px; cursor: pointer; font-weight: 600; }
  .btn-sm { background: #1A2230; color: #fff; border: 1px solid rgba(255,255,255,0.1); padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; }
  .btn-sm.danger { color: #FF4D4D; border-color: rgba(255,77,77,0.3); }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 12px; border-bottom: 1px solid rgba(255,255,255,0.08); font-size: 14px; }
  th { color: rgba(255,255,255,0.6); font-weight: 600; }
  .badge { padding: 4px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }
  .badge-ok { background: rgba(39,209,124,0.15); color: #27D17C; }
  .badge-err { background: rgba(255,77,77,0.15); color: #FF4D4D; }
  .err-text { color: #FF4D4D; font-size: 13px; margin-top: 8px; }
  .muted { color: rgba(255,255,255,0.6); }
  pre { background: #0F1420; padding: 14px; border-radius: 8px; overflow-x: auto; color: #FF7A1A; font-family: monospace; }
</style>
