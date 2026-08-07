<script lang="ts">
  import { onMount } from 'svelte';
  import { apiFetch } from '$lib/api';
  import type { User, UserGroup } from '$lib/types';
  import Modal from '$lib/components/Modal.svelte';
  import QRCode from '$lib/components/QRCode.svelte';
  import { showToast } from '$lib/components/Toast.svelte';

  interface Inbound { id: number; remark: string; protocol: string; port: number; }

  let users = $state<User[]>([]);
  let groups = $state<UserGroup[]>([]);
  let inbounds = $state<Inbound[]>([]);
  let loading = $state(true);

  // create user
  let newUsername = $state('');
  let newGroupId = $state<number | undefined>(undefined);
  let newLimitGB = $state(0);
  let newExpireDays = $state(0);
  let createErr = $state('');

  // sub modal
  let subModalOpen = $state(false);
  let activeSubUser = $state<User | null>(null);
  let subFormat = $state<'v2ray' | 'clash' | 'sing-box'>('v2ray');
  const subUrl = $derived.by(() => {
    if (!activeSubUser) return '';
    const base = `${window.location.origin}/sub/${activeSubUser.sub_token}`;
    return subFormat === 'v2ray' ? base : `${base}/${subFormat}`;
  });

  // manage (edit + assign) modal
  let manageOpen = $state(false);
  let mUser = $state<User | null>(null);
  let mLimitGB = $state(0);
  let mExpireDays = $state(0);
  let mStatus = $state('active');
  let mGroupId = $state<number | undefined>(undefined);
  let mAssigned = $state<Set<number>>(new Set());
  let mInherited = $state<Set<number>>(new Set());

  // groups modal
  let groupOpen = $state(false);
  let gEditing = $state<UserGroup | null>(null);
  let gName = $state('');
  let gDesc = $state('');
  let gInbounds = $state<Set<number>>(new Set());

  async function loadData() {
    loading = true;
    try {
      users = await apiFetch<User[]>('/admin/users');
      groups = await apiFetch<UserGroup[]>('/admin/groups');
      inbounds = await apiFetch<Inbound[]>('/admin/inbounds');
    } catch (err: any) {
      showToast(err.message || 'Failed to load users', 'error');
    } finally {
      loading = false;
    }
  }

  async function createUser() {
    createErr = '';
    if (!newUsername.trim()) { createErr = 'Username is required'; return; }
    try {
      await apiFetch('/admin/users', {
        method: 'POST',
        body: JSON.stringify({ username: newUsername.trim(), group_id: newGroupId,
          data_limit_gb: newLimitGB || 0, expire_days: newExpireDays || 0 }),
      });
      newUsername = ''; newLimitGB = 0; newExpireDays = 0;
      showToast('User created', 'success');
      await loadData();
    } catch (err: any) { createErr = err.message || 'Failed to create user'; }
  }

  async function setStatus(user: User, status: string) {
    try {
      await apiFetch(`/admin/users/${user.id}`, { method: 'PATCH', body: JSON.stringify({ status }) });
      showToast(`User ${status}`, 'info');
      await loadData();
    } catch (err: any) { showToast(err.message || 'Failed to update user', 'error'); }
  }

  async function resetCreds(user: User) {
    if (!confirm(`Reset ${user.username}'s credentials (UUID + sub token)? Existing configs stop working.`)) return;
    try {
      await apiFetch(`/admin/users/${user.id}/reset-credentials`, { method: 'POST' });
      showToast('Credentials reset', 'success');
      await loadData();
    } catch (err: any) { showToast(err.message || 'Failed to reset', 'error'); }
  }

  async function deleteUser(id: number) {
    if (!confirm('Delete this user?')) return;
    try {
      await apiFetch(`/admin/users/${id}`, { method: 'DELETE' });
      showToast('User deleted', 'info');
      await loadData();
    } catch (err: any) { showToast(err.message || 'Failed to delete', 'error'); }
  }

  function openSubModal(user: User) { activeSubUser = user; subModalOpen = true; }
  async function copySubUrl() {
    try { await navigator.clipboard.writeText(subUrl); showToast('Copied', 'success'); }
    catch (_) { showToast('Failed to copy', 'error'); }
  }

  // --- manage (edit + assign inbounds) ---
  async function openManage(user: User) {
    mUser = user;
    mLimitGB = Math.round(((user as any).data_limit || 0) / (1024 ** 3));
    mStatus = (user as any).status || 'active';
    mGroupId = user.group_id;
    mExpireDays = 0;
    mAssigned = new Set();
    mInherited = new Set();
    try {
      const res = await apiFetch<{ assignments: { direct: number[]; inherited: number[] } }>(`/admin/users/${user.id}`);
      mAssigned = new Set(res.assignments?.direct || []);
      mInherited = new Set(res.assignments?.inherited || []);
    } catch (_) {}
    manageOpen = true;
  }

  function toggleAssign(id: number) {
    const s = new Set(mAssigned);
    if (s.has(id)) s.delete(id); else s.add(id);
    mAssigned = s;
  }

  async function saveManage() {
    if (!mUser) return;
    try {
      const patch: Record<string, any> = { status: mStatus, group_id: mGroupId, data_limit: mLimitGB * 1024 ** 3 };
      if (mExpireDays > 0) patch.expire_at = new Date(Date.now() + mExpireDays * 86400_000).toISOString();
      await apiFetch(`/admin/users/${mUser.id}`, { method: 'PATCH', body: JSON.stringify(patch) });
      await apiFetch(`/admin/users/${mUser.id}/inbounds`, { method: 'PUT', body: JSON.stringify({ inbound_ids: [...mAssigned] }) });
      showToast('User updated + inbounds assigned', 'success');
      manageOpen = false;
      await loadData();
    } catch (err: any) { showToast(err.message || 'Failed to save', 'error'); }
  }

  // --- groups ---
  function openGroupNew() { gEditing = null; gName = ''; gDesc = ''; gInbounds = new Set(); groupOpen = true; }
  function openGroupEdit(g: UserGroup) {
    gEditing = g; gName = g.name; gDesc = (g as any).description || '';
    gInbounds = new Set(((g as any).inbound_ids || []) as number[]); groupOpen = true;
  }
  function toggleGroupInbound(id: number) {
    const s = new Set(gInbounds); if (s.has(id)) s.delete(id); else s.add(id); gInbounds = s;
  }
  async function saveGroup() {
    if (!gName.trim()) { showToast('Group name required', 'error'); return; }
    try {
      if (gEditing) {
        await apiFetch(`/admin/groups/${gEditing.id}`, { method: 'PATCH',
          body: JSON.stringify({ name: gName, description: gDesc, inbound_ids: [...gInbounds] }) });
      } else {
        const g = await apiFetch<{ id: number }>('/admin/groups', { method: 'POST',
          body: JSON.stringify({ name: gName, description: gDesc }) });
        if (gInbounds.size) {
          await apiFetch(`/admin/groups/${g.id}`, { method: 'PATCH', body: JSON.stringify({ inbound_ids: [...gInbounds] }) });
        }
      }
      showToast('Group saved', 'success'); groupOpen = false; await loadData();
    } catch (err: any) { showToast(err.message || 'Failed to save group', 'error'); }
  }
  async function deleteGroup(g: UserGroup) {
    if (!confirm(`Delete group "${g.name}"?`)) return;
    try { await apiFetch(`/admin/groups/${g.id}`, { method: 'DELETE' }); showToast('Group deleted', 'info'); await loadData(); }
    catch (err: any) { showToast(err.message || 'Failed to delete group', 'error'); }
  }

  function fmtBytes(b?: number) {
    if (!b) return '∞';
    const gb = b / 1024 ** 3;
    return gb >= 1 ? `${gb.toFixed(1)} GB` : `${(b / 1024 ** 2).toFixed(0)} MB`;
  }

  onMount(loadData);
</script>

<div class="view-header">
  <h2>Users &amp; Subscriptions</h2>
</div>

<div class="card">
  <h3>Add user</h3>
  <div class="row">
    <input placeholder="username" bind:value={newUsername} />
    <select bind:value={newGroupId}>
      <option value={undefined}>No group</option>
      {#each groups as g}<option value={g.id}>{g.name}</option>{/each}
    </select>
    <input type="number" placeholder="limit GB (0=∞)" bind:value={newLimitGB} title="data limit in GB" />
    <input type="number" placeholder="expire days (0=never)" bind:value={newExpireDays} title="expire in N days" />
    <button class="primary" data-testid="create-user" onclick={createUser}>Create</button>
  </div>
  {#if createErr}<p class="err">{createErr}</p>{/if}
</div>

<div class="card">
  {#if loading}<p class="muted">Loading…</p>
  {:else}
    <table data-testid="users-table">
      <thead><tr><th>User</th><th>Group</th><th>Limit</th><th>Used</th><th>Status</th><th>Sub token</th><th>Actions</th></tr></thead>
      <tbody>
        {#each users as u (u.id)}
          <tr>
            <td><strong>{u.username}</strong></td>
            <td>{groups.find(g => g.id === u.group_id)?.name || '—'}</td>
            <td>{fmtBytes((u as any).data_limit)}</td>
            <td>{fmtBytes((u as any).used_traffic)}</td>
            <td><span class="badge {(u as any).status === 'active' ? 'ok' : 'off'}">{(u as any).status || 'active'}</span></td>
            <td><code>{u.sub_token}</code></td>
            <td class="acts">
              <button class="sm" data-testid="manage-user" onclick={() => openManage(u)}>Manage</button>
              <button class="sm" onclick={() => openSubModal(u)}>Sub</button>
              <button class="sm" onclick={() => setStatus(u, (u as any).status === 'active' ? 'disabled' : 'active')}>{(u as any).status === 'active' ? 'Disable' : 'Enable'}</button>
              <button class="sm" onclick={() => resetCreds(u)}>Reset</button>
              <button class="sm danger" onclick={() => deleteUser(u.id)}>Delete</button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

<div class="card">
  <div class="ghead"><h3>Groups</h3><button class="sm" data-testid="new-group" onclick={openGroupNew}>+ New group</button></div>
  {#if groups.length === 0}<p class="muted">No groups. A group bundles inbounds and assigns them to all its users.</p>
  {:else}
    <table>
      <thead><tr><th>Name</th><th>Description</th><th>Inbounds</th><th></th></tr></thead>
      <tbody>
        {#each groups as g (g.id)}
          <tr>
            <td><strong>{g.name}</strong></td>
            <td class="muted">{(g as any).description || '—'}</td>
            <td>{((g as any).inbound_ids || []).length}</td>
            <td class="acts">
              <button class="sm" onclick={() => openGroupEdit(g)}>Edit</button>
              <button class="sm danger" onclick={() => deleteGroup(g)}>Delete</button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

<!-- Manage user modal -->
<Modal title={'Manage · ' + (mUser?.username || '')} isOpen={manageOpen} onClose={() => manageOpen = false}>
  <div class="mgrid">
    <label>Status<select bind:value={mStatus}><option value="active">active</option><option value="disabled">disabled</option></select></label>
    <label>Group<select bind:value={mGroupId}><option value={undefined}>No group</option>{#each groups as g}<option value={g.id}>{g.name}</option>{/each}</select></label>
    <label>Data limit (GB, 0=∞)<input type="number" bind:value={mLimitGB} /></label>
    <label>Extend expiry (days from now, 0=leave)<input type="number" bind:value={mExpireDays} /></label>
  </div>
  <h4>Assign inbounds to this user</h4>
  <div class="assign" data-testid="assign-inbounds">
    {#each inbounds as inb}
      <label class="chk">
        <input type="checkbox" checked={mAssigned.has(inb.id)} disabled={mInherited.has(inb.id)} onchange={() => toggleAssign(inb.id)} />
        {inb.remark || inb.protocol} <span class="muted">:{inb.port} {inb.protocol}{mInherited.has(inb.id) ? ' (from group)' : ''}</span>
      </label>
    {/each}
    {#if inbounds.length === 0}<p class="muted">No inbounds yet — create one in the Inbounds tab first.</p>{/if}
  </div>
  <button class="primary" data-testid="save-manage" onclick={saveManage}>Save</button>
</Modal>

<!-- Group modal -->
<Modal title={gEditing ? 'Edit group' : 'New group'} isOpen={groupOpen} onClose={() => groupOpen = false}>
  <div class="mgrid">
    <label>Name<input data-testid="group-name" bind:value={gName} /></label>
    <label>Description<input bind:value={gDesc} /></label>
  </div>
  <h4>Inbounds in this group (assigned to all its users)</h4>
  <div class="assign">
    {#each inbounds as inb}
      <label class="chk"><input type="checkbox" checked={gInbounds.has(inb.id)} onchange={() => toggleGroupInbound(inb.id)} /> {inb.remark || inb.protocol} <span class="muted">:{inb.port}</span></label>
    {/each}
  </div>
  <button class="primary" data-testid="save-group" onclick={saveGroup}>Save group</button>
</Modal>

<!-- Sub modal -->
<Modal title={'Subscription · ' + (activeSubUser?.username || '')} isOpen={subModalOpen} onClose={() => subModalOpen = false}>
  <div class="mgrid">
    <label>Format<select bind:value={subFormat}><option value="v2ray">v2ray</option><option value="clash">clash</option><option value="sing-box">sing-box</option></select></label>
  </div>
  <div class="uri-row"><code>{subUrl}</code><button class="sm" onclick={copySubUrl}>Copy</button></div>
  {#if subUrl}<div class="qr"><QRCode value={subUrl} size={190} /></div>{/if}
</Modal>

<style>
  .view-header h2 { margin: 0 0 20px; font-size: 20px; }
  .card { background: #141A24; border: 1px solid rgba(255,255,255,0.08); border-radius: 14px; padding: 20px; margin-bottom: 20px; }
  .card h3 { margin: 0 0 14px; font-size: 14px; }
  .ghead { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
  .row { display: flex; gap: 10px; flex-wrap: wrap; }
  .row input, .row select { flex: 1; min-width: 120px; }
  input, select { background: #0F1420; border: 1px solid rgba(255,255,255,0.12); color: #fff; padding: 9px 10px; border-radius: 8px; font: inherit; font-size: 13px; box-sizing: border-box; width: 100%; }
  .primary { background: #FF7A1A; color: #1a1204; border: none; font-weight: 700; padding: 10px 16px; border-radius: 8px; cursor: pointer; white-space: nowrap; }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 10px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.07); font-size: 13px; }
  th { color: rgba(255,255,255,0.55); font-size: 12px; }
  .acts { display: flex; gap: 6px; flex-wrap: wrap; }
  .sm { padding: 5px 10px; font-size: 12px; border-radius: 6px; background: #1A2230; color: #fff; border: 1px solid rgba(255,255,255,0.1); cursor: pointer; }
  .sm.danger { background: rgba(255,77,77,0.15); color: #FF4D4D; border-color: rgba(255,77,77,0.3); }
  .badge { padding: 3px 9px; border-radius: 12px; font-size: 11px; font-weight: 600; }
  .badge.ok { background: rgba(39,209,124,0.15); color: #27D17C; }
  .badge.off { background: rgba(255,255,255,0.1); color: rgba(255,255,255,0.6); }
  .muted { color: rgba(255,255,255,0.45); }
  .err { color: #FF4D4D; font-size: 13px; margin-top: 8px; }
  .mgrid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 14px; }
  .mgrid label { display: flex; flex-direction: column; gap: 5px; font-size: 12px; color: rgba(255,255,255,0.7); }
  h4 { margin: 8px 0 10px; font-size: 13px; color: #FF9A4A; }
  .assign { display: flex; flex-direction: column; gap: 7px; max-height: 260px; overflow-y: auto; margin-bottom: 14px; }
  .chk { display: flex; align-items: center; gap: 8px; font-size: 13px; color: #fff; }
  .chk input { width: auto; }
  .uri-row { display: flex; gap: 8px; align-items: center; margin-bottom: 10px; }
  .uri-row code { flex: 1; background: #0F1420; padding: 10px; border-radius: 8px; font-size: 12px; word-break: break-all; color: #27D17C; }
  .qr { display: flex; justify-content: center; padding: 10px; background: #fff; border-radius: 10px; }
</style>
