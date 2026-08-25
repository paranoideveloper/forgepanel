<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
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

  // subscription defaults (routing preset + TLS fragment) applied to every
  // generated sing-box/Xray/Clash config.
  interface FancyTheme { id: string; label: string; template: string; front: string; proto: string; sample: string; }
  interface SubSettings { routing_preset: string; fragment: boolean; presets: string[]; name_template?: string; name_tokens?: string[]; pattern?: string; pattern_modes?: string[]; front_domain?: string; front_mode?: string; front_modes?: string[]; fancy_themes?: FancyTheme[]; }
  let subSettings = $state<SubSettings | null>(null);
  const routingLabels: Record<string, string> = {
    iran: 'Iran (bypass Iran + block ads/malware)',
    full: 'Full (bypass Iran + block ads/malware/porn/QUIC)',
    block: 'Block-only (ads/malware, no Iran bypass)',
    off: 'Off (no routing rules)'
  };

  async function saveSubSettings() {
    if (!subSettings) return;
    try {
      await apiFetch('/admin/settings/subscription', {
        method: 'POST',
        body: JSON.stringify({ routing_preset: subSettings.routing_preset, fragment: subSettings.fragment, name_template: subSettings.name_template ?? '', pattern: subSettings.pattern ?? 'off', front_domain: subSettings.front_domain ?? '', front_mode: subSettings.front_mode ?? 'none' })
      });
      showToast('Subscription defaults saved', 'success');
    } catch (err: any) {
      showToast(err.message || 'Failed to save', 'error');
    }
  }

  // Fancy wizard: apply a styled theme (sets the name template + fronting model
  // server-side in one step) together with the operator's camouflage domain.
  async function applyFancyTheme(theme: FancyTheme) {
    if (!subSettings) return;
    try {
      const res = await apiFetch<{ name_template?: string; front_domain?: string; front_mode?: string }>('/admin/settings/subscription', {
        method: 'POST',
        body: JSON.stringify({ fancy_theme: theme.id, front_domain: subSettings.front_domain ?? '' })
      });
      subSettings.name_template = res.name_template ?? theme.template;
      subSettings.front_mode = res.front_mode ?? theme.front;
      showToast(`Applied theme “${theme.label}” (${theme.front === 'none' ? 'no fronting' : theme.front.toUpperCase()})`, 'success');
    } catch (err: any) {
      showToast(err.message || 'Failed to apply theme', 'error');
    }
  }

  async function loadData() {
    loading = true;
    try {
      users = await apiFetch<User[]>('/admin/users');
      groups = await apiFetch<UserGroup[]>('/admin/groups');
      inbounds = await apiFetch<Inbound[]>('/admin/inbounds');
      subSettings = await apiFetch<SubSettings>('/admin/settings/subscription');
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
    if (!confirm(`Reset ${user.username}'s credentials (UUID, password and subscription token)? Existing configs stop working.`)) return;
    try {
      // The handler refuses a request that names nothing to rotate
      // ("specify at least one of uuid, password, sub_token"), so posting an
      // empty body made credential rotation impossible from the panel.
      await apiFetch(`/admin/users/${user.id}/reset-credentials`, {
        method: 'POST',
        body: JSON.stringify({ uuid: true, password: true, sub_token: true })
      });
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

  // "Online" = the user moved traffic within the last few minutes (the poll
  // cycle stamps last_seen_at whenever they transfer). Generous 3-minute window
  // so a default ~60s poll comfortably marks an active user online.
  const ONLINE_WINDOW_MS = 3 * 60 * 1000;
  function isOnline(u: any): boolean {
    if (!u?.last_seen_at) return false;
    return Date.now() - new Date(u.last_seen_at).getTime() < ONLINE_WINDOW_MS;
  }
  function lastSeenLabel(u: any): string {
    if (!u?.last_seen_at) return 'never seen';
    const s = Math.floor((Date.now() - new Date(u.last_seen_at).getTime()) / 1000);
    if (s < 60) return `active ${s}s ago`;
    const m = Math.floor(s / 60);
    if (m < 60) return `last seen ${m}m ago`;
    const h = Math.floor(m / 60);
    if (h < 24) return `last seen ${h}h ago`;
    return `last seen ${Math.floor(h / 24)}d ago`;
  }

  // Refresh just the user rows periodically so the presence dots stay live
  // without a full reload or a page refresh. Silent — never toasts on failure.
  let presenceTimer: ReturnType<typeof setInterval> | undefined;
  async function refreshUsers() {
    try { users = await apiFetch<User[]>('/admin/users'); } catch (_) { /* keep last good */ }
  }
  onMount(() => {
    loadData();
    presenceTimer = setInterval(refreshUsers, 30_000);
  });
  onDestroy(() => { if (presenceTimer) clearInterval(presenceTimer); });
</script>

<div class="view-header">
  <h2>Users &amp; Subscriptions</h2>
</div>

{#if subSettings}
  <div class="card" data-testid="sub-settings">
    <h3>Subscription defaults</h3>
    <p class="hint">Applied to every generated sing-box / Xray / Clash config. Clients can still override per-link with <code>?routing=</code> and <code>?fragment=</code>.</p>
    <div class="row">
      <label class="field">
        <span>Routing rules</span>
        <select bind:value={subSettings.routing_preset} data-testid="routing-preset">
          {#each subSettings.presets as p}<option value={p}>{routingLabels[p] || p}</option>{/each}
        </select>
      </label>
      <label class="field checkbox">
        <input type="checkbox" bind:checked={subSettings.fragment} data-testid="fragment-toggle" />
        <span>TLS Fragment (Xray, DPI evasion)</span>
      </label>
      <label class="field">
        <span>Pattern (unsafe-uTLS)</span>
        <select bind:value={subSettings.pattern} data-testid="pattern-mode" title="Adds cs=/fm=/fp=unsafe to VLESS/Trojan/VMess links — the 'patterniha' anti-DPI variant">
          {#each (subSettings.pattern_modes ?? ['off','only','both']) as m}<option value={m}>{m === 'off' ? 'Off (normal)' : m === 'only' ? 'Pattern only' : 'Both (normal + pattern)'}</option>{/each}
        </select>
      </label>
      <button class="primary" data-testid="save-sub-settings" onclick={saveSubSettings}>Save</button>
    </div>
    <p class="hint">Pattern adds <code>cs</code> (cipher-suites) + <code>fm</code> (TLS fragment) + <code>fp=unsafe</code> to VLESS/Trojan/VMess links — the anti-DPI meta. Per link: <code>?patt=1</code> (pattern) or <code>?patt=both</code>. Needs a recent Xray client (v2rayNG ≥ 1.9 / v2rayN / Husi).</p>
    <div class="row" style="margin-top:10px">
      <label class="field" style="flex:1;min-width:280px">
        <span>Config name template <span class="hint" style="font-weight:400">— blank = keep each inbound's own name</span></span>
        <input bind:value={subSettings.name_template} placeholder="{'{FLAG} {NAME}'}" data-testid="name-template" />
      </label>
    </div>
    <p class="hint">Tokens: {#each (subSettings.name_tokens ?? []) as tk}<code style="margin-right:4px">{tk}</code>{/each} — e.g. <code>{'{FLAG} {NAME} · {NET}'}</code> → <b>🇩🇪 Berlin · ws</b>. Set a country per inbound for the flag.</p>
  </div>

  <div class="card" data-testid="fancy-wizard">
    <h3>✨ Fancy config wizard</h3>
    <p class="hint">Set a camouflage domain, pick a styled theme, and every config in the subscription is renamed and fronted behind that domain — the same look Iranian channels ship. Applies to all subscriptions; clear the theme to go back to plain names.</p>
    <div class="row">
      <label class="field" style="flex:1;min-width:240px">
        <span>Camouflage domain <span class="hint" style="font-weight:400">— e.g. aparat.com, taskulu.com</span></span>
        <input bind:value={subSettings.front_domain} placeholder="aparat.com" data-testid="front-domain" />
      </label>
      <label class="field">
        <span>Fronting model</span>
        <select bind:value={subSettings.front_mode} data-testid="front-mode" title="How the domain is applied to each config">
          {#each (subSettings.front_modes ?? ['none','sni','cdn']) as m}<option value={m}>{m === 'none' ? 'None (raw)' : m === 'sni' ? 'SNI + Host camouflage' : 'CDN domain-fronting'}</option>{/each}
        </select>
      </label>
      <button class="primary" data-testid="save-front" onclick={saveSubSettings}>Save domain</button>
    </div>
    <p class="hint"><b>SNI + Host</b>: keep the real server address but present the domain as TLS SNI + Host header (works on any server / REALITY). <b>CDN</b>: set only the Host header and route through a Host-aware CDN (plaintext-WS behind a domestic CDN). Picking a theme sets the recommended model automatically.</p>
    {#if subSettings.fancy_themes && subSettings.fancy_themes.length}
      <div class="theme-grid">
        {#each subSettings.fancy_themes as th}
          <button type="button" class="theme-card" class:active={subSettings.name_template === th.template} data-testid={'theme-' + th.id} onclick={() => applyFancyTheme(th)} title={`${th.label} · ${th.front} · suits ${th.proto}`}>
            <span class="theme-sample">{th.sample}</span>
            <span class="theme-meta">{th.label} · <b>{th.front === 'none' ? 'raw' : th.front.toUpperCase()}</b></span>
          </button>
        {/each}
      </div>
    {/if}
  </div>
{/if}

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
            <td>
              <span class="presence {isOnline(u) ? 'online' : 'offline'}" title={lastSeenLabel(u)}></span>
              <strong>{u.username}</strong>
            </td>
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
  .hint { color: rgba(255,255,255,0.55); font-size: 13px; margin: 0 0 12px; }
  .field { display: flex; flex-direction: column; gap: 4px; font-size: 12px; color: rgba(255,255,255,0.6); flex: 1; min-width: 160px; }
  .field.checkbox { flex-direction: row; align-items: center; gap: 8px; font-size: 13px; color: rgba(255,255,255,0.85); }
  .field.checkbox input { flex: none; width: 16px; height: 16px; }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 10px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.07); font-size: 13px; }
  th { color: rgba(255,255,255,0.55); font-size: 12px; }
  .acts { display: flex; gap: 6px; flex-wrap: wrap; }
  .sm { padding: 5px 10px; font-size: 12px; border-radius: 6px; background: #1A2230; color: #fff; border: 1px solid rgba(255,255,255,0.1); cursor: pointer; }
  .sm.danger { background: rgba(255,77,77,0.15); color: #FF4D4D; border-color: rgba(255,77,77,0.3); }
  .badge { padding: 3px 9px; border-radius: 12px; font-size: 11px; font-weight: 600; }
  .badge.ok { background: rgba(39,209,124,0.15); color: #27D17C; }
  .badge.off { background: rgba(255,255,255,0.1); color: rgba(255,255,255,0.6); }
  .presence { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 8px; vertical-align: middle; cursor: help; }
  .presence.online { background: #27D17C; box-shadow: 0 0 6px #27D17C; }
  .presence.offline { background: rgba(255,255,255,0.22); }
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
  .theme-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 10px; margin-top: 12px; }
  .theme-card { display: flex; flex-direction: column; gap: 6px; align-items: flex-start; text-align: left; background: #0F1420; border: 1px solid rgba(255,255,255,0.10); border-radius: 10px; padding: 12px; cursor: pointer; transition: border-color .15s, background .15s; }
  .theme-card:hover { border-color: rgba(39,209,124,0.5); background: #121a26; }
  .theme-card.active { border-color: #27D17C; background: rgba(39,209,124,0.10); }
  .theme-sample { font-size: 14px; color: #fff; word-break: break-word; }
  .theme-meta { font-size: 11px; color: rgba(255,255,255,0.55); }
  .theme-meta b { color: #27D17C; font-weight: 600; }
</style>
