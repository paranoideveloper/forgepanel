<script lang="ts">
  import { onMount } from 'svelte';
  import { apiFetch } from '$lib/api';
  import type { User, UserGroup } from '$lib/types';
  import Modal from '$lib/components/Modal.svelte';
  import QRCode from '$lib/components/QRCode.svelte';
  import { showToast } from '$lib/components/Toast.svelte';

  let users = $state<User[]>([]);
  let groups = $state<UserGroup[]>([]);
  let loading = $state(true);

  let newUsername = $state('');
  let newGroupId = $state<number | undefined>(undefined);
  let newNotes = $state('');
  let createErr = $state('');

  // Subscription modal state
  let subModalOpen = $state(false);
  let activeSubUser = $state<User | null>(null);
  let subFormat = $state<'v2ray' | 'clash' | 'sing-box'>('v2ray');

  let subUrl = $derived(() => {
    if (!activeSubUser) return '';
    const origin = window.location.origin;
    const base = `${origin}/sub/${activeSubUser.sub_token}`;
    return subFormat === 'v2ray' ? base : `${base}/${subFormat}`;
  });

  async function loadData() {
    loading = true;
    try {
      users = await apiFetch<User[]>('/admin/users');
      groups = await apiFetch<UserGroup[]>('/admin/usergroups');
    } catch (err: any) {
      showToast(err.message || 'Failed to load users', 'error');
    } finally {
      loading = false;
    }
  }

  async function createUser() {
    createErr = '';
    if (!newUsername.trim()) {
      createErr = 'Username is required';
      return;
    }
    try {
      await apiFetch('/admin/users', {
        method: 'POST',
        body: JSON.stringify({
          username: newUsername.trim(),
          group_id: newGroupId,
          notes: newNotes.trim()
        })
      });
      newUsername = '';
      newNotes = '';
      showToast('User created successfully', 'success');
      await loadData();
    } catch (err: any) {
      createErr = err.message || 'Failed to create user';
    }
  }

  async function toggleUser(user: User) {
    try {
      await apiFetch(`/admin/users/${user.id}`, {
        method: 'PUT',
        body: JSON.stringify({ enabled: !user.enabled })
      });
      showToast(`User ${user.username} ${!user.enabled ? 'enabled' : 'disabled'}`, 'info');
      await loadData();
    } catch (err: any) {
      showToast(err.message || 'Failed to update user', 'error');
    }
  }

  async function rotateSubToken(user: User) {
    if (!confirm(`Rotate subscription token for ${user.username}? Active clients will disconnect.`)) return;
    try {
      await apiFetch(`/admin/users/${user.id}/rotate-token`, { method: 'POST' });
      showToast('Subscription token rotated', 'success');
      await loadData();
    } catch (err: any) {
      showToast(err.message || 'Failed to rotate token', 'error');
    }
  }

  async function deleteUser(id: number) {
    if (!confirm('Are you sure you want to delete this user?')) return;
    try {
      await apiFetch(`/admin/users/${id}`, { method: 'DELETE' });
      showToast('User deleted', 'info');
      await loadData();
    } catch (err: any) {
      showToast(err.message || 'Failed to delete user', 'error');
    }
  }

  function openSubModal(user: User) {
    activeSubUser = user;
    subModalOpen = true;
  }

  async function copySubUrl() {
    const url = subUrl();
    try {
      await navigator.clipboard.writeText(url);
      showToast('Subscription URL copied to clipboard', 'success');
    } catch (_) {
      showToast('Failed to copy URL', 'error');
    }
  }

  onMount(() => {
    loadData();
  });
</script>

<div class="view-header">
  <h2>User Accounts & Subscriptions</h2>
  <button class="btn-primary" onclick={loadData}>Refresh</button>
</div>

<div class="card">
  <h3>Create User Account</h3>
  <div class="form-grid">
    <input type="text" bind:value={newUsername} placeholder="Username" />
    <select bind:value={newGroupId}>
      <option value={undefined}>No Group (Default)</option>
      {#each groups as g}
        <option value={g.id}>{g.name}</option>
      {/each}
    </select>
    <input type="text" bind:value={newNotes} placeholder="Notes / Tag" />
    <button class="btn-primary" onclick={createUser}>Create User</button>
  </div>
  {#if createErr}<p class="err-text">{createErr}</p>{/if}
</div>

<div class="card table-card">
  {#if loading}
    <p class="muted">Loading users...</p>
  {:else}
    <table>
      <thead>
        <tr>
          <th>User</th>
          <th>Group</th>
          <th>Sub Token</th>
          <th>Status</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {#each users as u}
          <tr>
            <td>
              <strong>{u.username}</strong>
              {#if u.notes}<span class="user-notes">{u.notes}</span>{/if}
            </td>
            <td><code>{groups.find(g => g.id === u.group_id)?.name || 'Default'}</code></td>
            <td><code>{u.sub_token.slice(0, 8)}...</code></td>
            <td>
              <span class="badge {u.enabled ? 'badge-ok' : 'badge-err'}">
                {u.enabled ? 'Active' : 'Disabled'}
              </span>
            </td>
            <td class="action-cell">
              <button class="btn-sm" onclick={() => openSubModal(u)}>Sub Link</button>
              <button class="btn-sm" onclick={() => toggleUser(u)}>{u.enabled ? 'Disable' : 'Enable'}</button>
              <button class="btn-sm" onclick={() => rotateSubToken(u)}>Rotate</button>
              <button class="btn-sm danger" onclick={() => deleteUser(u.id)}>Delete</button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

<Modal title="Subscription Details" isOpen={subModalOpen} onClose={() => subModalOpen = false}>
  {#if activeSubUser}
    <div class="sub-modal-content">
      <p class="muted">Share this link or QR code with <strong>{activeSubUser.username}</strong>:</p>
      
      <div class="format-tabs">
        <button class:active={subFormat === 'v2ray'} onclick={() => subFormat = 'v2ray'}>V2Ray / Universal</button>
        <button class:active={subFormat === 'clash'} onclick={() => subFormat = 'clash'}>Clash Meta</button>
        <button class:active={subFormat === 'sing-box'} onclick={() => subFormat = 'sing-box'}>Sing-Box</button>
      </div>

      <div class="qr-container">
        <QRCode value={subUrl()} size={180} />
      </div>

      <div class="url-box">
        <input type="text" readonly value={subUrl()} />
        <button class="btn-primary" onclick={copySubUrl}>Copy Link</button>
      </div>
    </div>
  {/if}
</Modal>

<style>
  .view-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
  .view-header h2 { margin: 0; font-size: 20px; font-weight: 650; }
  .card { background: #141A24; border: 1px solid rgba(255,255,255,0.08); border-radius: 14px; padding: 20px; margin-bottom: 20px; }
  .card h3 { margin: 0 0 16px; font-size: 14px; text-transform: uppercase; color: rgba(255,255,255,0.7); }
  .form-grid { display: grid; grid-template-columns: 1fr 1fr 1fr auto; gap: 12px; }
  input, select { background: #0F1420; border: 1px solid rgba(255,255,255,0.12); color: #fff; padding: 10px; border-radius: 8px; font: inherit; }
  .btn-primary { background: #FF7A1A; color: #1a1204; border: none; font-weight: 700; padding: 10px 16px; border-radius: 8px; cursor: pointer; }
  .btn-sm { background: #1A2230; color: #fff; border: 1px solid rgba(255,255,255,0.1); padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; }
  .btn-sm.danger { color: #FF4D4D; border-color: rgba(255,77,77,0.3); }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 12px; border-bottom: 1px solid rgba(255,255,255,0.08); font-size: 14px; }
  th { color: rgba(255,255,255,0.6); font-weight: 600; }
  .user-notes { display: block; font-size: 12px; color: rgba(255,255,255,0.5); }
  .badge { padding: 4px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }
  .badge-ok { background: rgba(39,209,124,0.15); color: #27D17C; }
  .badge-err { background: rgba(255,77,77,0.15); color: #FF4D4D; }
  .action-cell { display: flex; gap: 6px; }
  .err-text { color: #FF4D4D; font-size: 13px; margin-top: 8px; }
  .muted { color: rgba(255,255,255,0.6); }

  .sub-modal-content { display: flex; flex-direction: column; gap: 16px; align-items: center; text-align: center; }
  .format-tabs { display: flex; gap: 8px; background: #0F1420; padding: 4px; border-radius: 8px; }
  .format-tabs button { background: none; border: none; color: rgba(255,255,255,0.6); padding: 6px 12px; font-size: 12px; border-radius: 6px; cursor: pointer; }
  .format-tabs button.active { background: #FF7A1A; color: #1a1204; font-weight: 700; }
  .url-box { display: flex; gap: 8px; width: 100%; }
  .url-box input { flex: 1; }
</style>
