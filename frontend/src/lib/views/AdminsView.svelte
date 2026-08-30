<script lang="ts">
	import { tr } from '$lib/i18n';
  import { onMount } from 'svelte';
  import { apiFetch } from '$lib/api';
  import Modal from '$lib/components/Modal.svelte';
  import { showToast } from '$lib/components/Toast.svelte';

  // The reseller model — roles, per-admin user quotas, traffic credit, owner
  // scoping — was enforced throughout the backend with no way to create a
  // second admin, so the whole of multi-tenancy was unreachable. This is that
  // surface.
  interface AdminAccount {
    id: number;
    username: string;
    role: string;
    disabled: boolean;
    two_factor_enabled: boolean;
    user_quota: number;
    traffic_credit: number;
    users_owned: number;
    traffic_allocated: number;
    created_at: string;
  }

  const ROLES = [
    { id: 'owner', help: 'Full control, including panel configuration and these accounts.' },
    { id: 'admin', help: 'Manages inbounds and customers; cannot reconfigure the panel.' },
    { id: 'reseller', help: 'Manages only their own customers, within their quota.' },
    { id: 'viewer', help: 'Read-only dashboards.' }
  ];

  let admins = $state<AdminAccount[]>([]);
  let loading = $state(true);
  let loadError = $state('');

  let newUsername = $state('');
  let newPassword = $state('');
  let newRole = $state('reseller');
  let newQuota = $state(0);
  let newCreditGB = $state(0);
  let createErr = $state('');

  let editing = $state<AdminAccount | null>(null);
  let editRole = $state('');
  let editQuota = $state(0);
  let editCreditGB = $state(0);
  let editPassword = $state('');
  let editErr = $state('');

  let deleting = $state<AdminAccount | null>(null);
  let reassignTo = $state<number | null>(null);
  let deleteErr = $state('');

  const GB = 1024 * 1024 * 1024;
  const toGB = (bytes: number) => Math.round((bytes / GB) * 100) / 100;

  // An owner count of one is why most of the refusals exist: losing it cannot be
  // undone from inside the panel, since no account could grant the role back.
  const enabledOwners = $derived(admins.filter((a) => a.role === 'owner' && !a.disabled).length);

  async function load() {
    loading = true;
    loadError = '';
    try {
      admins = await apiFetch<AdminAccount[]>('/admin/admins');
    } catch (err: any) {
      loadError = err.message || tr('admins.failed_to_load_admin_accounts');
    } finally {
      loading = false;
    }
  }

  async function create() {
    createErr = '';
    if (!newUsername.trim()) {
      createErr = 'A username is required';
      return;
    }
    if (newPassword.length < 8) {
      createErr = 'The password must be at least 8 characters';
      return;
    }
    try {
      await apiFetch('/admin/admins', {
        method: 'POST',
        body: JSON.stringify({
          username: newUsername.trim(),
          password: newPassword,
          role: newRole,
          user_quota: Number(newQuota) || 0,
          traffic_credit: Math.round((Number(newCreditGB) || 0) * GB)
        })
      });
      newUsername = '';
      newPassword = '';
      newQuota = 0;
      newCreditGB = 0;
      showToast(tr('admins.account_created'), 'success');
      await load();
    } catch (err: any) {
      createErr = err.message || tr('admins.failed_to_create_the_account');
    }
  }

  function openEdit(a: AdminAccount) {
    editing = a;
    editRole = a.role;
    editQuota = a.user_quota;
    editCreditGB = toGB(a.traffic_credit);
    editPassword = '';
    editErr = '';
  }

  async function saveEdit() {
    if (!editing) return;
    editErr = '';
    const body: Record<string, unknown> = {};
    // Only send what changed. A quota of 0 means UNLIMITED, so sending every
    // field on every edit would silently remove limits the operator never
    // touched.
    if (editRole !== editing.role) body.role = editRole;
    if (Number(editQuota) !== editing.user_quota) body.user_quota = Number(editQuota);
    const credit = Math.round((Number(editCreditGB) || 0) * GB);
    if (credit !== editing.traffic_credit) body.traffic_credit = credit;
    if (editPassword) {
      if (editPassword.length < 8) {
        editErr = 'The password must be at least 8 characters';
        return;
      }
      body.password = editPassword;
    }
    if (Object.keys(body).length === 0) {
      editing = null;
      return;
    }
    try {
      await apiFetch(`/admin/admins/${editing.id}`, { method: 'PATCH', body: JSON.stringify(body) });
      const changedAuthority = 'role' in body || 'password' in body;
      editing = null;
      showToast(
        changedAuthority
          ? 'Saved — that account has been signed out everywhere'
          : 'Saved',
        'success'
      );
      await load();
    } catch (err: any) {
      editErr = err.message || tr('admins.failed_to_save');
    }
  }

  async function toggleDisabled(a: AdminAccount) {
    try {
      await apiFetch(`/admin/admins/${a.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ disabled: !a.disabled })
      });
      showToast(a.disabled ? tr('admins.account_enabled') : tr('admins.account_disabled_and_signed_out'), 'info');
      await load();
    } catch (err: any) {
      showToast(err.message || tr('admins.failed_to_change_the_account'), 'error');
    }
  }

  function openDelete(a: AdminAccount) {
    deleting = a;
    deleteErr = '';
    // Default the destination to some other account, so the common case is one
    // click and the operator still sees where the customers are going.
    reassignTo = admins.find((x) => x.id !== a.id)?.id ?? null;
  }

  async function confirmDelete() {
    if (!deleting) return;
    deleteErr = '';
    // A user whose owner no longer exists belongs to nobody: no reseller sees
    // them, quota accounting stops counting them, and nothing can manage them
    // while they keep being served.
    const q = deleting.users_owned > 0 ? `?reassign_to=${reassignTo}` : '';
    if (deleting.users_owned > 0 && !reassignTo) {
      deleteErr = 'Choose which account inherits this one’s customers';
      return;
    }
    try {
      await apiFetch(`/admin/admins/${deleting.id}${q}`, { method: 'DELETE' });
      deleting = null;
      showToast(tr('admins.account_deleted'), 'info');
      await load();
    } catch (err: any) {
      deleteErr = err.message || tr('admins.failed_to_delete_the_account');
    }
  }

  onMount(load);
</script>

<div class="view-header">
  <h2>{tr('admins.admins_amp_resellers')}</h2>
  <button class="btn-primary" onclick={load}>{tr('admins.refresh')}</button>
</div>

<div class="card">
  <h3>{tr('admins.create_account')}</h3>
  <div class="form-grid">
    <input bind:value={newUsername} placeholder={tr('admins.username')} data-testid="new-admin-username" />
    <input type="password" bind:value={newPassword} placeholder={tr('admins.password_min_8_characters')} data-testid="new-admin-password" />
    <select bind:value={newRole} data-testid="new-admin-role">
      {#each ROLES as r}<option value={r.id}>{r.id}</option>{/each}
    </select>
    <button class="btn-primary" onclick={create}>{tr('admins.create')}</button>
  </div>
  <p class="muted">{ROLES.find((r) => r.id === newRole)?.help}</p>
  {#if newRole === 'reseller'}
    <div class="form-grid">
      <label class="fg">
        <span>{tr('admins.user_quota_0_unlimited')}</span>
        <input type="number" min="0" bind:value={newQuota} data-testid="new-admin-quota" />
      </label>
      <label class="fg">
        <span>{tr('admins.traffic_credit_gb_0_unlimited')}</span>
        <input type="number" min="0" bind:value={newCreditGB} />
      </label>
    </div>
  {/if}
  {#if createErr}<p class="err-text" data-testid="create-error">{createErr}</p>{/if}
</div>

<div class="card table-card">
  {#if loading}
    <p class="muted">{tr('admins.loading_accounts')}</p>
  {:else if loadError}
    <p class="err-text">{loadError}</p>
  {:else if admins.length === 0}
    <p class="muted">{tr('admins.no_accounts_yet')}</p>
  {:else}
    <table>
      <thead>
        <tr>
          <th>{tr('admins.username')}</th>
          <th>{tr('admins.role')}</th>
          <th>{tr('admins.customers')}</th>
          <th>{tr('admins.quota')}</th>
          <th>{tr('admins.traffic_credit')}</th>
          <th>2FA</th>
          <th>{tr('admins.status')}</th>
          <th>{tr('admins.actions')}</th>
        </tr>
      </thead>
      <tbody>
        {#each admins as a}
          <tr class:dimmed={a.disabled}>
            <td><strong>{a.username}</strong></td>
            <td><span class="badge">{a.role}</span></td>
            <td>{a.users_owned}</td>
            <td>{a.user_quota === 0 ? '∞' : `${a.users_owned} / ${a.user_quota}`}</td>
            <td>
              {a.traffic_credit === 0
                ? '∞'
                : `${toGB(a.traffic_allocated)} / ${toGB(a.traffic_credit)} GB`}
            </td>
            <td>{a.two_factor_enabled ? '✓' : '—'}</td>
            <td>
              <span class="badge {a.disabled ? 'badge-err' : 'badge-ok'}">
                {a.disabled ? tr('admins.disabled') : tr('admins.active')}
              </span>
            </td>
            <td class="actions-cell">
              <button class="btn-sm" onclick={() => openEdit(a)}>{tr('admins.edit')}</button>
              <button class="btn-sm" onclick={() => toggleDisabled(a)}>
                {a.disabled ? tr('admins.enable') : tr('admins.disable')}
              </button>
              <button class="btn-sm danger" onclick={() => openDelete(a)}>{tr('admins.delete')}</button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    {#if enabledOwners <= 1}
      <p class="muted">
        {tr('admins.this_panel_has_one_owner_it')}
      </p>
    {/if}
  {/if}
</div>

<Modal isOpen={!!editing} title={`Edit ${editing?.username ?? ''}`} onClose={() => (editing = null)}>
  <div class="form-grid">
    <label class="fg">
      <span>{tr('admins.role')}</span>
      <select bind:value={editRole} data-testid="edit-admin-role">
        {#each ROLES as r}<option value={r.id}>{r.id}</option>{/each}
      </select>
    </label>
    <label class="fg">
      <span>{tr('admins.user_quota_0_unlimited')}</span>
      <input type="number" min="0" bind:value={editQuota} />
    </label>
    <label class="fg">
      <span>{tr('admins.traffic_credit_gb_0_unlimited')}</span>
      <input type="number" min="0" bind:value={editCreditGB} />
    </label>
    <label class="fg">
      <span>{tr('admins.new_password_leave_blank_to_keep')}</span>
      <input type="password" bind:value={editPassword} data-testid="edit-admin-password" />
    </label>
  </div>
  <p class="muted">
    {tr('admins.changing_the_role_or_the_password')}
  </p>
  {#if editErr}<p class="err-text">{editErr}</p>{/if}
  <button class="btn-primary" onclick={saveEdit}>{tr('admins.save')}</button>
</Modal>

<Modal isOpen={!!deleting} title={`Delete ${deleting?.username ?? ''}`} onClose={() => (deleting = null)}>
  {#if deleting && deleting.users_owned > 0}
    <p class="muted">
      {tr('admins.this_account_owns')} <strong>{deleting.users_owned}</strong> {tr('admins.customer_s_choose_who_inherits_them')}
    </p>
    <select bind:value={reassignTo} data-testid="reassign-target">
      {#each admins.filter((x) => x.id !== deleting?.id) as other}
        <option value={other.id}>{other.username} ({other.role})</option>
      {/each}
    </select>
  {:else}
    <p class="muted">{tr('admins.this_account_owns_no_customers')}</p>
  {/if}
  {#if deleteErr}<p class="err-text" data-testid="delete-error">{deleteErr}</p>{/if}
  <div class="form-grid">
    <button class="btn-secondary" onclick={() => (deleting = null)}>{tr('admins.cancel')}</button>
    <button class="btn-secondary danger" onclick={confirmDelete}>{tr('admins.delete_account')}</button>
  </div>
</Modal>

<style>
  .view-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
  .view-header h2 { margin: 0; font-size: 20px; font-weight: 650; }
  .card { background: var(--card); border: 1px solid var(--ln-3); border-radius: 14px; padding: 20px; margin-bottom: 20px; }
  .card h3 { margin: 0 0 16px; font-size: 14px; text-transform: uppercase; color: var(--t-3); }
  .form-grid { display: flex; flex-wrap: wrap; gap: 12px; align-items: flex-end; }
  .fg { display: flex; flex-direction: column; gap: 4px; font-size: 12px; color: var(--t-3); }
  input, select { background: var(--bg); border: 1px solid var(--ln-5); color: var(--fg); padding: 10px; border-radius: 8px; font: inherit; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: start; padding: 10px 12px; border-bottom: 1px solid var(--ln-2); font-size: 13px; }
  th { color: var(--t-6); font-weight: 600; text-transform: uppercase; font-size: 11px; }
  tr.dimmed { opacity: 0.55; }
  .actions-cell { display: flex; gap: 6px; }
  .badge { padding: 3px 8px; border-radius: 999px; font-size: 11px; background: var(--ln-3); }
  .badge-ok { background: rgba(46,160,67,0.15); color: var(--ok-2); }
  .badge-err { background: rgba(248,81,73,0.15); color: var(--bad-2); }
  .muted { color: var(--t-6); font-size: 13px; }
  .err-text { color: var(--bad-2); font-size: 13px; }
  .btn-primary, .btn-secondary, .btn-sm { border-radius: 8px; border: 1px solid transparent; cursor: pointer; font: inherit; }
  .btn-primary { background: var(--acc); color: var(--card-deep); padding: 10px 16px; font-weight: 600; }
  .btn-secondary { background: var(--ln-3); color: var(--fg); padding: 10px 16px; }
  .btn-sm { background: var(--ln-3); color: var(--fg); padding: 5px 10px; font-size: 12px; }
  .danger { background: rgba(248,81,73,0.15); color: var(--bad-2); border-color: rgba(248,81,73,0.4); }
</style>
