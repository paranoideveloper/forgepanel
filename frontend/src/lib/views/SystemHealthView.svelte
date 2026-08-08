<script lang="ts">
  import { onMount } from 'svelte';
  import { apiFetch } from '$lib/api';
  import type { HealthDetail, TwoFASetup, AuditLog } from '$lib/types';
  import Modal from '$lib/components/Modal.svelte';
  import QRCode from '$lib/components/QRCode.svelte';
  import { showToast } from '$lib/components/Toast.svelte';

  let healthDetail = $state<HealthDetail | null>(null);
  let auditLogs = $state<AuditLog[]>([]);
  let loading = $state(true);

  // Panel Doctor
  let doctor = $state<any>(null);
  let doctorBusy = $state(false);
  async function runDoctor() {
    doctorBusy = true;
    try { doctor = await apiFetch('/admin/doctor'); }
    catch (e: any) { showToast(e.message || 'doctor failed', 'error'); }
    finally { doctorBusy = false; }
  }

  // 2FA state
  let twoFAEnabled = $state(false);
  let twoFAData = $state<TwoFASetup | null>(null);
  let twoFAModalOpen = $state(false);
  let verifyCode = $state('');

  // Change Password state
  let oldPass = $state('');
  let newPass = $state('');
  let passErr = $state('');

  // Docker Compose state
  let composeYaml = $state('');
  let composeProfiles = $state('default');

  async function loadData() {
    loading = true;
    try {
      healthDetail = await apiFetch<HealthDetail>('/admin/health/detail');
      await runDoctor();
      auditLogs = await apiFetch<AuditLog[]>('/admin/stats');
      const user = await apiFetch<{ two_factor_enabled?: boolean }>('/admin/me');
      twoFAEnabled = !!user.two_factor_enabled;
    } catch (err: any) {
      showToast(err.message || 'Failed to load system state', 'error');
    } finally {
      loading = false;
    }
  }

  async function setup2FA() {
    try {
      twoFAData = await apiFetch<TwoFASetup>('/admin/2fa/setup', { method: 'POST' });
      twoFAModalOpen = true;
    } catch (err: any) {
      showToast(err.message || 'Failed to initiate 2FA setup', 'error');
    }
  }

  async function enable2FA() {
    if (!verifyCode.trim()) return;
    try {
      await apiFetch('/admin/2fa/enable', {
        method: 'POST',
        body: JSON.stringify({ code: verifyCode.trim() })
      });
      twoFAEnabled = true;
      twoFAModalOpen = false;
      showToast('Two-Factor Authentication enabled', 'success');
    } catch (err: any) {
      showToast(err.message || 'Invalid 2FA code', 'error');
    }
  }

  async function disable2FA() {
    if (!confirm('Disable 2FA security?')) return;
    try {
      await apiFetch('/admin/2fa/disable', { method: 'POST' });
      twoFAEnabled = false;
      showToast('Two-Factor Authentication disabled', 'info');
    } catch (err: any) {
      showToast(err.message || 'Failed to disable 2FA', 'error');
    }
  }

  async function changePassword() {
    passErr = '';
    if (!oldPass || !newPass) {
      passErr = 'Both old and new passwords are required';
      return;
    }
    try {
      await apiFetch('/admin/change-password', {
        method: 'POST',
        body: JSON.stringify({ old_password: oldPass, new_password: newPass })
      });
      oldPass = '';
      newPass = '';
      showToast('Password changed successfully', 'success');
    } catch (err: any) {
      passErr = err.message || 'Failed to change password';
    }
  }

  async function fetchCompose() {
    try {
      const res = await apiFetch<{ compose: string }>(`/deploy/compose?profiles=${encodeURIComponent(composeProfiles)}`);
      composeYaml = res.compose || '';
      showToast('Docker Compose config generated', 'success');
    } catch (err: any) {
      showToast('Failed to generate compose config', 'error');
    }
  }

  onMount(() => {
    loadData();
  });
</script>

<div class="view-header">
  <h2>System Diagnostics &amp; Security</h2>
  <button class="btn-primary" onclick={loadData}>Refresh</button>
</div>

<div class="card" data-testid="doctor-panel">
  <div class="doctor-head">
    <h3>Panel Doctor</h3>
    <button class="btn-sm" onclick={runDoctor} disabled={doctorBusy}>{doctorBusy ? 'Running…' : 'Run diagnostics'}</button>
  </div>
  {#if doctor?.health}
    <p class="doctor-state">
      Overall: <span class="badge {doctor.health.state === 'healthy' ? 'ok' : doctor.health.state === 'not_configured' ? 'warn' : 'err'}">{doctor.health.label || doctor.health.state}</span>
    </p>
    {#if doctor.health.subsystems}
      <div class="doctor-grid">
        {#each doctor.health.subsystems as sub}
          <div class="doctor-item">
            <span class="badge {sub.state === 'healthy' ? 'ok' : sub.state === 'not_configured' ? 'warn' : 'err'}">{sub.state}</span>
            <div><strong>{sub.label}</strong><span class="muted">{sub.summary}</span></div>
          </div>
        {/each}
      </div>
    {/if}
    {#if doctor.inbounds?.length}
      <p class="muted" style="margin-top:12px">{doctor.inbounds.length} inbound(s) checked.</p>
    {/if}
  {:else}
    <p class="muted">Click “Run diagnostics” to check the panel, engines, certs and inbounds.</p>
  {/if}
</div>

<div class="card">
  <h3>Two-Factor Authentication (2FA)</h3>
  <p class="muted">Protect administrative access with Time-based One-Time Passwords (TOTP).</p>
  <div>
    {#if twoFAEnabled}
      <span class="badge badge-ok">2FA Enabled</span>
      <button class="btn-secondary danger" style="margin-left:12px" onclick={disable2FA}>Disable 2FA</button>
    {:else}
      <button class="btn-primary" onclick={setup2FA}>Enable 2FA Authenticator</button>
    {/if}
  </div>
</div>

<div class="card">
  <h3>Change Administrator Password</h3>
  <div class="form-grid">
    <input type="password" bind:value={oldPass} placeholder="Current Password" />
    <input type="password" bind:value={newPass} placeholder="New Password" />
    <button class="btn-primary" onclick={changePassword}>Update Password</button>
  </div>
  {#if passErr}<p class="err-text">{passErr}</p>{/if}
</div>

{#if healthDetail}
  <div class="card">
    <h3>Subsystem Health Matrix</h3>
    <div class="subsystem-grid">
      {#each healthDetail.subsystems as s}
        <div class="subsystem-card">
          <span class="dot {s.state === 'healthy' ? 'ok' : s.state === 'not_configured' ? 'warn' : 'err'}"></span>
          <div class="subsystem-info">
            <strong>{s.label || s.key}</strong>
            <span class="detail">{s.detail || s.summary}</span>
          </div>
        </div>
      {/each}
    </div>
  </div>
{/if}

<div class="card">
  <h3>Export Docker Compose Configuration</h3>
  <div class="form-row">
    <input type="text" bind:value={composeProfiles} placeholder="Profiles (default,dns,all)" />
    <button class="btn-secondary" onclick={fetchCompose}>Generate YAML</button>
  </div>
  {#if composeYaml}
    <pre><code>{composeYaml}</code></pre>
  {/if}
</div>

<Modal title="Set Up 2FA Authenticator" isOpen={twoFAModalOpen} onClose={() => twoFAModalOpen = false}>
  {#if twoFAData}
    <div class="twofa-content">
      <p class="muted">Scan this QR code with Google Authenticator or 1Password:</p>
      {#if twoFAData.qr_code_url}
        <QRCode value={twoFAData.qr_code_url} size={200} />
      {/if}
      <p class="secret-text">Secret key: <code>{twoFAData.secret}</code></p>
      <div class="form-row" style="margin-top:12px">
        <input type="text" bind:value={verifyCode} placeholder="6-digit TOTP code" />
        <button class="btn-primary" onclick={enable2FA}>Verify &amp; Activate</button>
      </div>
    </div>
  {/if}
</Modal>

<style>
  .view-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
  .view-header h2 { margin: 0; font-size: 20px; font-weight: 650; }
  .card { background: #141A24; border: 1px solid rgba(255,255,255,0.08); border-radius: 14px; padding: 20px; margin-bottom: 20px; }
  .card h3 { margin: 0 0 16px; font-size: 14px; text-transform: uppercase; color: rgba(255,255,255,0.7); }
  .form-grid { display: grid; grid-template-columns: 1fr 1fr auto; gap: 12px; }
  .form-row { display: flex; gap: 12px; }
  .form-row input { flex: 1; }
  input { background: #0F1420; border: 1px solid rgba(255,255,255,0.12); color: #fff; padding: 10px; border-radius: 8px; font: inherit; }
  .btn-primary { background: #FF7A1A; color: #1a1204; border: none; font-weight: 700; padding: 10px 16px; border-radius: 8px; cursor: pointer; }
  .btn-secondary { background: #1A2230; color: #fff; border: 1px solid rgba(255,255,255,0.1); padding: 10px 16px; border-radius: 8px; cursor: pointer; font-weight: 600; }
  .btn-secondary.danger { color: #FF4D4D; border-color: rgba(255,77,77,0.3); }
  .badge { padding: 4px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }
  .badge-ok { background: rgba(39,209,124,0.15); color: #27D17C; }
  .subsystem-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; }
  .subsystem-card { display: flex; align-items: center; gap: 12px; background: #0F1420; padding: 12px; border-radius: 8px; }
  .dot { width: 10px; height: 10px; border-radius: 50%; flex: none; }
  .dot.ok { background: #27D17C; }
  .dot.warn { background: #FFB020; }
  .dot.err { background: #FF4D4D; }
  .subsystem-info { display: flex; flex-direction: column; }
  .detail { font-size: 12px; color: rgba(255,255,255,0.5); }
  .err-text { color: #FF4D4D; font-size: 13px; margin-top: 8px; }
  .muted { color: rgba(255,255,255,0.6); }
  pre { background: #0F1420; padding: 14px; border-radius: 8px; overflow-x: auto; color: #FF7A1A; font-family: monospace; margin-top: 12px; }
  .twofa-content { display: flex; flex-direction: column; align-items: center; gap: 12px; text-align: center; }
  .secret-text { font-size: 13px; color: rgba(255,255,255,0.7); }
  .doctor-head { display: flex; justify-content: space-between; align-items: center; }
  .btn-sm { background: #1A2230; color: #fff; border: 1px solid rgba(255,255,255,0.12); padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; }
  .doctor-state { margin: 8px 0 12px; font-size: 14px; }
  .doctor-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 10px; }
  .doctor-item { display: flex; gap: 10px; align-items: flex-start; background: #0F1420; padding: 10px 12px; border-radius: 8px; }
  .doctor-item strong { display: block; font-size: 13px; }
  .doctor-item .muted { font-size: 11px; }
  .badge.ok { background: rgba(39,209,124,0.15); color: #27D17C; }
  .badge.warn { background: rgba(255,180,0,0.15); color: #FFB400; }
  .badge.err { background: rgba(255,77,77,0.15); color: #FF4D4D; }
  .subsystem-info strong { word-break: break-word; }
  .subsystem-info .detail { font-size: 12px; color: rgba(255,255,255,0.55); word-break: break-word; }

  /* Mobile: stack multi-column grids and rows so nothing runs off-screen. */
  @media (max-width: 768px) {
    .form-grid { grid-template-columns: 1fr; }
    .form-row { flex-direction: column; align-items: stretch; }
    .form-row input, .form-row button { width: 100%; }
    .subsystem-grid { grid-template-columns: 1fr; }
    .doctor-grid { grid-template-columns: 1fr; }
    .view-header { flex-wrap: wrap; gap: 10px; }
  }
</style>
