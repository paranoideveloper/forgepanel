<script lang="ts">
	import { tr } from '$lib/i18n';
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
  // The enroll token is minted once and never returned again, so the command is
  // held only for as long as this modal is open.
  let enrolledName = $state('');
  let enrollFingerprint = $state('');

  // A node whose disk fills stops writing configs and goes quiet, so this is
  // shown as used-of-total rather than a bare number, and flagged past 90%.
  function diskLabel(n: Node): string {
    if (!n.disk_total_mb) return '—';
    const used = n.disk_used_mb ?? 0;
    const gb = (v: number) => (v / 1024).toFixed(1);
    return `${gb(used)} / ${gb(n.disk_total_mb)} GB`;
  }
  function diskPct(n: Node): number {
    if (!n.disk_total_mb) return 0;
    return ((n.disk_used_mb ?? 0) / n.disk_total_mb) * 100;
  }
  function diskCritical(n: Node): boolean {
    return diskPct(n) >= 90;
  }
  function diskTitle(n: Node): string {
    if (!n.disk_total_mb) return 'not reported';
    const p = Math.round(diskPct(n));
    return diskCritical(n) ? `${p}% full — the node will stop writing configs` : `${p}% full`;
  }

  // Uptime separates a node that is connected from one whose core is
  // crash-looping: the agent reports in fine while the core it supervises never
  // stays up long enough to serve anything.
  function coreLabel(n: Node): string {
    const s = n.core_uptime_sec ?? 0;
    if (!s) return 'down';
    if (s < 90) return `${s}s`;
    if (s < 3600) return `${Math.round(s / 60)}m`;
    if (s < 86400) return `${Math.round(s / 3600)}h`;
    return `${Math.round(s / 86400)}d`;
  }

  function lastSeenLabel(n: Node): string {
    if (!n.last_seen) return 'never';
    const age = (Date.now() - new Date(n.last_seen).getTime()) / 1000;
    if (!Number.isFinite(age) || age < 0) return '—';
    if (age < 90) return `${Math.round(age)}s ago`;
    if (age < 3600) return `${Math.round(age / 60)}m ago`;
    if (age < 86400) return `${Math.round(age / 3600)}h ago`;
    return `${Math.round(age / 86400)}d ago`;
  }

  async function loadNodes() {
    loading = true;
    try {
      nodes = await apiFetch<Node[]>('/admin/nodes');
    } catch (err: any) {
      showToast(err.message || tr('nodes.failed_to_load_nodes'), 'error');
    } finally {
      loading = false;
    }
  }

  async function registerNode() {
    createErr = '';
    // Only the name is required. The handler deliberately treats the address as
    // optional — a node behind NAT or on a dynamic IP reports its own address
    // when it registers — so demanding one here blocked exactly the nodes that
    // most need enrolling.
    if (!newName.trim()) {
      createErr = 'A node name is required';
      return;
    }
    try {
      // POST /admin/nodes does not exist; this used to 404 on every attempt, so
      // registering a node from the panel could not work. /nodes/enroll is the
      // real route: it creates the node AND mints the one-time enroll token,
      // returning the exact command to run on it.
      const res = await apiFetch<{
        name: string;
        enroll_command: string;
        panel_fingerprint?: string;
      }>('/admin/nodes/enroll', {
        method: 'POST',
        body: JSON.stringify({ name: newName.trim(), address: newAddress.trim() })
      });
      enrolledName = res.name || newName.trim();
      enrollFingerprint = res.panel_fingerprint || '';
      // The REAL command, with the real token — not a placeholder the operator
      // has to fill in from somewhere the panel never tells them.
      installScript = res.enroll_command;
      scriptModalOpen = true;
      newName = '';
      newAddress = '';
      showToast(tr('nodes.node_registered_run_the_command_on'), 'success');
      await loadNodes();
    } catch (err: any) {
      createErr = err.message || tr('nodes.failed_to_register_node');
    }
  }

  async function deleteNode(id: number) {
    if (!confirm(tr('nodes.remove_this_node_from_the_cluster'))) return;
    try {
      await apiFetch(`/admin/nodes/${id}`, { method: 'DELETE' });
      showToast(tr('nodes.node_deleted'), 'info');
      await loadNodes();
    } catch (err: any) {
      showToast(err.message || tr('nodes.failed_to_delete_node'), 'error');
    }
  }

  // Registering a node is what mints its token, so there is no useful command to
  // show outside that flow: the token is one-time and the panel cannot reissue
  // it. This used to present a command containing the literal string
  // YOUR_ENROLL_TOKEN, which looks copy-pasteable and cannot work.
  function showInstallModal() {
    enrolledName = '';
    enrollFingerprint = '';
    installScript = '';
    scriptModalOpen = true;
  }

  async function copyScript() {
    try {
      await navigator.clipboard.writeText(installScript);
      showToast(tr('nodes.install_script_copied'), 'success');
    } catch (_) {
      showToast(tr('nodes.failed_to_copy_script'), 'error');
    }
  }

  onMount(() => {
    loadNodes();
  });
</script>

<div class="view-header">
  <h2>{tr('nodes.node_cluster_daemons')}</h2>
  <div class="actions">
    <button class="btn-secondary" onclick={showInstallModal}>{tr('nodes.install_agent_script')}</button>
    <button class="btn-primary" onclick={loadNodes}>{tr('nodes.refresh')}</button>
  </div>
</div>

<div class="card">
  <h3>{tr('nodes.register_remote_node_agent')}</h3>
  <div class="form-grid">
    <input type="text" bind:value={newName} placeholder={tr('nodes.node_name_e_g_eu_west')} />
    <input type="text" bind:value={newAddress} placeholder={tr('nodes.public_ip_or_domain_optional')} />
    <button class="btn-primary" onclick={registerNode}>{tr('nodes.register_node')}</button>
  </div>
  {#if createErr}<p class="err-text">{createErr}</p>{/if}
</div>

<div class="card table-card">
  {#if loading}
    <p class="muted">{tr('nodes.loading_node_cluster')}</p>
  {:else}
    <table>
      <thead>
        <tr>
          <th>{tr('nodes.node_name')}</th>
          <th>{tr('nodes.address')}</th>
          <th>CPU</th>
          <th>{tr('nodes.memory')}</th>
          <th>{tr('nodes.disk')}</th>
          <th>{tr('nodes.conns')}</th>
          <th>{tr('nodes.core')}</th>
          <th>{tr('nodes.last_seen')}</th>
          <th>{tr('nodes.status')}</th>
          <th>{tr('nodes.actions')}</th>
        </tr>
      </thead>
      <tbody>
        {#each nodes as n}
          <tr>
            <td><strong>{n.name}</strong></td>
            <td><code>{n.address}</code></td>
            <td>{Math.round(n.cpu || 0)}%</td>
            <td>{tr('nodes.mb', { p1: n.mem_mb || 0 })}</td>
            <td class={diskCritical(n) ? 'warn-cell' : ''} title={diskTitle(n)}>{diskLabel(n)}</td>
            <td>{n.tcp_conns ?? '—'}</td>
            <td title={n.core_version ? `core ${n.core_version}` : 'core version not reported'}>
              {coreLabel(n)}
            </td>
            <td title={n.last_seen || 'never'}>{lastSeenLabel(n)}</td>
            <td>
              <span class="badge {n.healthy ? 'badge-ok' : 'badge-err'}">
                {n.healthy ? 'Online' : 'Stale'}
              </span>
              {#if !n.enrolled}
                <span class="badge badge-warn" title={tr('nodes.registered_but_the_agent_has_never')}>
                  {tr('nodes.not_enrolled')}
                </span>
              {/if}
              {#if n.config_dirty}
                <span class="badge badge-warn" title={tr('nodes.the_node_is_running_an_older')}>
                  {tr('nodes.config_stale')}
                </span>
              {/if}
            </td>
            <td>
              <button class="btn-sm danger" onclick={() => deleteNode(n.id)}>{tr('nodes.remove')}</button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

<Modal title={tr('nodes.deploy_node_agent_forgenode')} isOpen={scriptModalOpen} onClose={() => scriptModalOpen = false}>
  {#if installScript}
    <p class="muted">
      {tr('nodes.run_this_on')} <strong>{enrolledName}</strong> {tr('nodes.as_root_it_downloads_the_agent')}
    </p>
    <pre><code data-testid="enroll-command">{installScript}</code></pre>
    <p class="err-text">
      {tr('nodes.the_enrollment_token_appears_once_if')}
    </p>
    {#if enrollFingerprint}
      <p class="muted">
        {tr('nodes.this_panel_serves_a_self_signed')}
      </p>
    {/if}
    <button class="btn-primary" onclick={copyScript}>{tr('nodes.copy_command')}</button>
  {:else}
    <p class="muted">
      {tr('nodes.register_a_node_above_to_get')}
    </p>
  {/if}
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
  th, td { text-align: start; padding: 12px; border-bottom: 1px solid rgba(255,255,255,0.08); font-size: 14px; }
  th { color: rgba(255,255,255,0.6); font-weight: 600; }
  .badge { padding: 4px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }
  .badge-ok { background: rgba(39,209,124,0.15); color: #27D17C; }
  .badge-err { background: rgba(255,77,77,0.15); color: #FF4D4D; }
  .err-text { color: #FF4D4D; font-size: 13px; margin-top: 8px; }
  .muted { color: rgba(255,255,255,0.6); }
  pre { background: #0F1420; padding: 14px; border-radius: 8px; overflow-x: auto; color: #FF7A1A; font-family: monospace; }
  .warn-cell { color: #d99b2b; font-weight: 600; }
  .badge-warn { background: rgba(217,155,43,0.15); color: #d99b2b; border: 1px solid rgba(217,155,43,0.4); }
</style>
