<script lang="ts">
	import { tr } from '$lib/i18n';
  import { onMount } from 'svelte';
  import { apiFetch } from '$lib/api';
  import type { Node } from '$lib/types';
  import Modal from '$lib/components/Modal.svelte';
  import NodeLogs from '$lib/components/NodeLogs.svelte';
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

  // The badge reads the state the SERVER derived, and does not re-derive one.
  //
  // The table used to compute "online" here from last_seen, because the server's
  // `healthy` column was only ever written true and a node that died an hour ago
  // still claimed to be Online. The server now derives a four-state answer on
  // every read — and three of those four states are things this file cannot see:
  // nothing in last_seen says a node was switched off by an operator, or that
  // its agent is reporting on time while the core it supervises refuses every
  // config it is handed. A second opinion computed here could only disagree with
  // the one the rest of the panel uses.
  const STATUS_CLASS: Record<string, string> = {
    connected: 'badge-ok',
    connecting: 'badge-warn',
    error: 'badge-err',
    disabled: 'badge-muted'
  };
  function statusClass(n: Node): string {
    return STATUS_CLASS[n.status] ?? 'badge-warn';
  }
  function statusLabel(n: Node): string {
    switch (n.status) {
      case 'connected':
        return tr('nodes.status_connected');
      case 'error':
        return tr('nodes.status_error');
      case 'disabled':
        return tr('nodes.status_disabled');
      default:
        return tr('nodes.status_connecting');
    }
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

  // Taking a node out of service is a control-plane action, not a label: the
  // panel refuses a disabled node's heartbeat, so it stops receiving config
  // bundles and drains instead of quietly serving yesterday's config while this
  // table says it is off.
  async function setDisabled(n: Node, disabled: boolean) {
    if (disabled && !confirm(tr('nodes.disable_confirm', { p1: n.name }))) return;
    try {
      await apiFetch(`/admin/nodes/${n.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ disabled })
      });
      showToast(disabled ? tr('nodes.node_disabled') : tr('nodes.node_enabled'), 'info');
      await loadNodes();
    } catch (err: any) {
      showToast(err.message || tr('nodes.failed_to_change_node_state'), 'error');
    }
  }

  // The node whose core output is being watched, or null when the panel is shut.
  let logsNode = $state<Node | null>(null);
  function openLogs(n: Node) {
    logsNode = n;
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
              <span
                class="badge {statusClass(n)}"
                data-testid="node-status-{n.id}"
                title={n.status_message || ''}
              >
                {statusLabel(n)}
              </span>
              {#if n.status_message}
                <span class="err-text status-msg" data-testid="node-status-msg-{n.id}">
                  {n.status_message}
                </span>
              {/if}
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
              <button class="btn-sm" onclick={() => openLogs(n)}>{tr('nodes.logs')}</button>
              <button class="btn-sm" onclick={() => setDisabled(n, !n.disabled)}>
                {n.disabled ? tr('nodes.enable') : tr('nodes.disable')}
              </button>
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

<Modal
  title={tr('nodes.logs_title', { p1: logsNode?.name })}
  isOpen={logsNode !== null}
  onClose={() => (logsNode = null)}
>
  {#if logsNode}
    <!-- Keyed by node id so opening the panel for a second node builds a fresh
         component, and therefore a fresh socket, instead of leaving the first
         node's stream running under the second node's title. -->
    {#key logsNode.id}
      <NodeLogs nodeId={logsNode.id} nodeName={logsNode.name} />
    {/key}
  {/if}
</Modal>

<style>
  .view-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
  .view-header h2 { margin: 0; font-size: 20px; font-weight: 650; }
  .actions { display: flex; gap: 10px; }
  .card { background: var(--card); border: 1px solid var(--ln-3); border-radius: 14px; padding: 20px; margin-bottom: 20px; }
  .card h3 { margin: 0 0 16px; font-size: 14px; text-transform: uppercase; color: var(--t-3); }
  .form-grid { display: grid; grid-template-columns: 1fr 1fr auto; gap: 12px; }
  input { background: var(--bg); border: 1px solid var(--ln-5); color: var(--fg); padding: 10px; border-radius: 8px; font: inherit; }
  .btn-primary { background: var(--acc); color: var(--acc-soft); border: none; font-weight: 700; padding: 10px 16px; border-radius: 8px; cursor: pointer; }
  .btn-secondary { background: var(--raised); color: var(--fg); border: 1px solid var(--ln-4); padding: 10px 16px; border-radius: 8px; cursor: pointer; font-weight: 600; }
  .btn-sm { background: var(--raised); color: var(--fg); border: 1px solid var(--ln-4); padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; }
  .btn-sm.danger { color: var(--bad); border-color: rgba(255,77,77,0.3); }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: start; padding: 12px; border-bottom: 1px solid var(--ln-3); font-size: 14px; }
  th { color: var(--t-5); font-weight: 600; }
  .badge { padding: 4px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }
  .badge-ok { background: rgba(39,209,124,0.15); color: var(--ok); }
  .badge-err { background: rgba(255,77,77,0.15); color: var(--bad); }
  .err-text { color: var(--bad); font-size: 13px; margin-top: 8px; }
  .muted { color: var(--t-5); }
  pre { background: var(--bg); padding: 14px; border-radius: 8px; overflow-x: auto; color: var(--acc); font-family: monospace; }
  .warn-cell { color: var(--warn); font-weight: 600; }
  .badge-warn { background: rgba(217,155,43,0.15); color: var(--warn); border: 1px solid rgba(217,155,43,0.4); }
  /* Deliberately off is not a fault: a disabled node must not wear the same red
     as one that died, or the operator learns to ignore red. */
  .badge-muted { background: var(--ln-3); color: var(--t-4); }
  .status-msg { display: block; margin-top: 4px; font-size: 11px; max-width: 22rem; }
</style>
