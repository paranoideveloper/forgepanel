<script lang="ts">
	import { tr } from '$lib/i18n';
  import { onMount } from 'svelte';
  import { apiFetch, setSession, clearSession, getAuthToken, onSessionExpired } from '$lib/api';
  import type { User, UserGroup, Node, SystemHealth } from '$lib/types';

  let token = $state(getAuthToken());
  let username = $state('admin');
  let password = $state('');
  let authError = $state('');

  let activeTab = $state<'overview' | 'users' | 'nodes'>('overview');
  let health = $state<SystemHealth | null>(null);
  let users = $state<User[]>([]);
  let groups = $state<UserGroup[]>([]);
  let nodes = $state<Node[]>([]);

  let newUsername = $state('');
  let newGroup = $state<number | undefined>(undefined);
  let userError = $state('');

  let newNodeName = $state('');
  let newNodeAddr = $state('');
  let nodeError = $state('');

  async function login(e?: Event) {
    if (e) e.preventDefault();
    authError = '';
    try {
      // Keep BOTH halves. Storing only the access token is why an expired
      // session used to fill the panel with bare 401s and no way back.
      const res = await apiFetch<{ access_token: string; refresh_token?: string }>('/login', {
        method: 'POST',
        body: JSON.stringify({ username, password })
      });
      token = res.access_token;
      setSession(res.access_token, res.refresh_token);
      await loadAll();
    } catch (err: any) {
      authError = err.message || tr('admin.authentication_failed');
    }
  }

  async function loadAll() {
    try {
      health = await apiFetch<SystemHealth>('/admin/overview');
      users = await apiFetch<User[]>('/admin/users');
      groups = await apiFetch<UserGroup[]>('/admin/groups');
      nodes = await apiFetch<Node[]>('/admin/nodes');
    } catch (err: any) {
      if (err.status === 401) {
        token = '';
        clearSession();
      }
    }
  }

  async function createUser() {
    userError = '';
    if (!newUsername.trim()) return;
    try {
      await apiFetch('/admin/users', {
        method: 'POST',
        body: JSON.stringify({ username: newUsername.trim(), group_id: newGroup })
      });
      newUsername = '';
      await loadAll();
    } catch (err: any) {
      userError = err.message || tr('admin.failed_to_create_user');
    }
  }

  async function toggleUser(user: User) {
    try {
      await apiFetch(`/admin/users/${user.id}`, {
        method: 'PUT',
        body: JSON.stringify({ enabled: !user.enabled })
      });
      await loadAll();
    } catch (err: any) {
      alert(err.message || tr('admin.failed_to_update_user_status'));
    }
  }

  async function createNode() {
    nodeError = '';
    if (!newNodeName.trim() || !newNodeAddr.trim()) return;
    try {
      await apiFetch('/admin/nodes', {
        method: 'POST',
        body: JSON.stringify({ name: newNodeName.trim(), address: newNodeAddr.trim() })
      });
      newNodeName = '';
      newNodeAddr = '';
      await loadAll();
    } catch (err: any) {
      nodeError = err.message || tr('admin.failed_to_register_node');
    }
  }

  async function deleteNode(id: number) {
    if (!confirm(tr('admin.remove_this_node'))) return;
    try {
      await apiFetch(`/admin/nodes/${id}`, { method: 'DELETE' });
      await loadAll();
    } catch (err: any) {
      alert(err.message || tr('admin.failed_to_delete_node'));
    }
  }

  onMount(() => {
    if (token) loadAll();
  });
</script>

<svelte:head>
  <title>{tr('admin.forgepanel_administration')}</title>
</svelte:head>

<div class="layout">
  <aside class="sidebar">
    <div class="brand">
      <span class="logo">⚡</span>
      <h2>ForgePanel</h2>
    </div>
    {#if token}
      <nav>
        <button class:active={activeTab === 'overview'} onclick={() => activeTab = 'overview'}>{tr('admin.overview')}</button>
        <button class:active={activeTab === 'users'} onclick={() => activeTab = 'users'}>{tr('admin.users', { length: users.length })}</button>
        <button class:active={activeTab === 'nodes'} onclick={() => activeTab = 'nodes'}>{tr('admin.nodes', { length: nodes.length })}</button>
      </nav>
    {/if}
  </aside>

  <main class="content">
    {#if !token}
      <div class="card login-box">
        <h2>{tr('admin.sign_in')}</h2>
        <form onsubmit={login}>
          <div class="form-group">
            <label for="u">{tr('admin.username')}</label>
            <input id="u" type="text" bind:value={username} required />
          </div>
          <div class="form-group">
            <label for="p">{tr('admin.password')}</label>
            <input id="p" type="password" bind:value={password} required />
          </div>
          <button type="submit" class="primary">{tr('admin.sign_in')}</button>
        </form>
        {#if authError}<p class="err">{authError}</p>{/if}
      </div>
    {:else}
      {#if activeTab === 'overview'}
        <section class="tab-pane">
          <h2>{tr('admin.system_health')}</h2>
          {#if health}
            <div class="stats-grid">
              <div class="stat-card">
                <span class="label">{tr('admin.status')}</span>
                <span class="value ok">{health.status}</span>
              </div>
              <div class="stat-card">
                <span class="label">{tr('admin.version')}</span>
                <span class="value">{health.version}</span>
              </div>
              <div class="stat-card">
                <span class="label">{tr('admin.active_nodes')}</span>
                <span class="value">{health.nodes_online} / {health.nodes_total}</span>
              </div>
            </div>
          {/if}
        </section>
      {:else if activeTab === 'users'}
        <section class="tab-pane">
          <h2>{tr('admin.user_accounts')}</h2>
          <div class="card">
            <h3>{tr('admin.add_new_user')}</h3>
            <div class="row">
              <input type="text" bind:value={newUsername} placeholder={tr('admin.username')} />
              <select bind:value={newGroup}>
                <option value={undefined}>{tr('admin.no_group')}</option>
                {#each groups as g}
                  <option value={g.id}>{g.name}</option>
                {/each}
              </select>
              <button onclick={createUser} class="primary">{tr('admin.create_user')}</button>
            </div>
            {#if userError}<p class="err">{userError}</p>{/if}
          </div>

          <table>
            <thead>
              <tr><th>ID</th><th>{tr('admin.username')}</th><th>{tr('admin.sub_token')}</th><th>{tr('admin.status')}</th><th>{tr('admin.actions')}</th></tr>
            </thead>
            <tbody>
              {#each users as u}
                <tr>
                  <td>{u.id}</td>
                  <td><strong>{u.username}</strong></td>
                  <td><code>{u.sub_token}</code></td>
                  <td>
                    <span class="badge {u.enabled ? 'ok' : 'err'}">
                      {u.enabled ? tr('admin.active') : tr('admin.disabled')}
                    </span>
                  </td>
                  <td>
                    <button class="sm" onclick={() => toggleUser(u)}>
                      {u.enabled ? tr('admin.disable') : tr('admin.enable')}
                    </button>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </section>
      {:else if activeTab === 'nodes'}
        <section class="tab-pane">
          <h2>{tr('admin.node_cluster')}</h2>
          <div class="card">
            <h3>{tr('admin.register_node')}</h3>
            <div class="row">
              <input type="text" bind:value={newNodeName} placeholder={tr('admin.node_name')} />
              <input type="text" bind:value={newNodeAddr} placeholder={tr('admin.address_ip_domain')} />
              <button onclick={createNode} class="primary">{tr('admin.register')}</button>
            </div>
            {#if nodeError}<p class="err">{nodeError}</p>{/if}
          </div>

          <table>
            <thead>
              <tr><th>{tr('admin.name')}</th><th>{tr('admin.address')}</th><th>CPU</th><th>{tr('admin.memory')}</th><th>{tr('admin.status')}</th><th>{tr('admin.actions')}</th></tr>
            </thead>
            <tbody>
              {#each nodes as n}
                <tr>
                  <td><strong>{n.name}</strong></td>
                  <td><code>{n.address}</code></td>
                  <td>{n.cpu}%</td>
                  <td>{tr('admin.mb', { mem_mb: n.mem_mb })}</td>
                  <td>
                    <span class="badge {n.healthy ? 'ok' : 'err'}">
                      {n.healthy ? tr('admin.online') : tr('admin.offline')}
                    </span>
                  </td>
                  <td>
                    <button class="sm danger" onclick={() => deleteNode(n.id)}>{tr('admin.delete')}</button>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </section>
      {/if}
    {/if}
  </main>
</div>

<style>
  :global(body) {
    margin: 0;
    font-family: system-ui, -apple-system, sans-serif;
    background: #0B0F16;
    color: rgba(255,255,255,0.92);
  }
  .layout { display: flex; min-height: 100vh; }
  .sidebar {
    width: 240px;
    background: #0F1420;
    border-inline-end: 1px solid rgba(255,255,255,0.08);
    padding: 24px 16px;
  }
  .brand { display: flex; align-items: center; gap: 10px; margin-bottom: 32px; }
  .brand h2 { margin: 0; font-size: 18px; color: #FF7A1A; }
  nav button {
    display: block;
    width: 100%;
    text-align: start;
    background: none;
    border: none;
    color: rgba(255,255,255,0.7);
    padding: 10px 14px;
    border-radius: 8px;
    cursor: pointer;
    font-size: 14px;
    margin-bottom: 4px;
  }
  nav button.active, nav button:hover {
    background: rgba(255,122,26,0.15);
    color: #FF7A1A;
    font-weight: 600;
  }
  .content { flex: 1; padding: 32px; max-width: 1000px; }
  .card {
    background: #141A24;
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 12px;
    padding: 20px;
    margin-bottom: 24px;
  }
  .login-box { max-width: 360px; margin: 60px auto; }
  .form-group { margin-bottom: 16px; }
  .form-group label { display: block; margin-bottom: 6px; font-size: 13px; color: rgba(255,255,255,0.7); }
  input, select {
    width: 100%;
    padding: 10px;
    background: #0B0F16;
    border: 1px solid rgba(255,255,255,0.12);
    border-radius: 8px;
    color: #fff;
    box-sizing: border-box;
  }
  button.primary {
    background: #FF7A1A;
    color: #1a1204;
    border: none;
    padding: 10px 18px;
    border-radius: 8px;
    font-weight: 700;
    cursor: pointer;
  }
  button.sm { padding: 6px 12px; font-size: 12px; border-radius: 6px; }
  button.danger { background: rgba(255,77,77,0.2); color: #FF4D4D; border: 1px solid #FF4D4D; }
  .row { display: flex; gap: 12px; align-items: center; }
  .row input, .row select { flex: 1; }
  .stats-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
  .stat-card { background: #141A24; padding: 20px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.08); }
  .stat-card .label { display: block; font-size: 12px; color: rgba(255,255,255,0.6); margin-bottom: 8px; }
  .stat-card .value { font-size: 24px; font-weight: 700; }
  .value.ok { color: #27D17C; }
  table { width: 100%; border-collapse: collapse; margin-top: 16px; }
  th, td { padding: 12px; text-align: start; border-bottom: 1px solid rgba(255,255,255,0.08); font-size: 14px; }
  th { color: rgba(255,255,255,0.6); font-weight: 600; }
  .badge { padding: 4px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }
  .badge.ok { background: rgba(39,209,124,0.15); color: #27D17C; }
  .badge.err { background: rgba(255,77,77,0.15); color: #FF4D4D; }
  .err { color: #FF4D4D; font-size: 13px; margin-top: 8px; }
</style>
