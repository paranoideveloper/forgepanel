<script lang="ts">
  import { onMount } from 'svelte';
  import { apiFetch } from '$lib/api';
  import type { CertStatus } from '$lib/types';
  import { showToast } from '$lib/components/Toast.svelte';

  let panelDomain = $state('');
  let certStatus = $state<CertStatus | null>(null);
  let loading = $state(true);

  let certPem = $state('');
  let keyPem = $state('');
  let importErr = $state('');

  let dnsCheckResult = $state<{ resolved: boolean; ip?: string } | null>(null);
  let checkingDns = $state(false);

  async function loadData() {
    loading = true;
    try {
      const res = await apiFetch<{ domain: string }>('/admin/panel-address');
      panelDomain = res.domain || '';
      certStatus = await apiFetch<CertStatus>('/admin/certs');
    } catch (err: any) {
      showToast(err.message || 'Failed to load TLS status', 'error');
    } finally {
      loading = false;
    }
  }

  async function updateDomain() {
    try {
      await apiFetch('/admin/panel-address', {
        method: 'POST',
        body: JSON.stringify({ domain: panelDomain.trim() })
      });
      showToast('Panel domain updated', 'success');
      await loadData();
    } catch (err: any) {
      showToast(err.message || 'Failed to update domain', 'error');
    }
  }

  async function checkDns() {
    if (!panelDomain.trim()) return;
    checkingDns = true;
    dnsCheckResult = null;
    try {
      dnsCheckResult = await apiFetch<{ resolved: boolean; ip?: string }>(`/admin/panel-address/dns-check?domain=${encodeURIComponent(panelDomain.trim())}`);
    } catch (err: any) {
      showToast('DNS check failed', 'error');
    } finally {
      checkingDns = false;
    }
  }

  async function importCert() {
    importErr = '';
    if (!certPem.trim() || !keyPem.trim()) {
      importErr = 'Both Certificate PEM and Private Key PEM are required';
      return;
    }
    try {
      await apiFetch('/admin/certs/import', {
        method: 'POST',
        body: JSON.stringify({ cert_pem: certPem.trim(), key_pem: keyPem.trim() })
      });
      certPem = '';
      keyPem = '';
      showToast('TLS Certificate imported successfully', 'success');
      await loadData();
    } catch (err: any) {
      importErr = err.message || 'Failed to import certificate';
    }
  }

  async function renewCert() {
    try {
      await apiFetch('/admin/panel-address/cert/renew', { method: 'POST' });
      showToast('ACME certificate renewal requested', 'info');
      await loadData();
    } catch (err: any) {
      showToast(err.message || 'Failed to renew certificate', 'error');
    }
  }

  onMount(() => {
    loadData();
  });
</script>

<div class="view-header">
  <h2>Certificates &amp; Panel Domain</h2>
  <button class="btn-primary" onclick={loadData}>Refresh</button>
</div>

<div class="card">
  <h3>Panel Domain &amp; Auto TLS (Let's Encrypt / ACME)</h3>
  <div class="form-row">
    <input type="text" bind:value={panelDomain} placeholder="panel.example.com" />
    <button class="btn-primary" onclick={updateDomain}>Save Domain</button>
    <button class="btn-secondary" onclick={checkDns} disabled={checkingDns}>
      {checkingDns ? 'Checking...' : 'Check DNS'}
    </button>
  </div>

  {#if dnsCheckResult}
    <div class="dns-box {dnsCheckResult.resolved ? 'ok' : 'err'}">
      {dnsCheckResult.resolved ? `DNS records resolved correctly (${dnsCheckResult.ip})` : 'DNS records failed to resolve'}
    </div>
  {/if}
</div>

{#if certStatus}
  <div class="card">
    <h3>Active TLS Certificate Status</h3>
    <div class="status-grid">
      <div><span class="lbl">Domain:</span> <strong>{certStatus.domain || 'N/A'}</strong></div>
      <div><span class="lbl">Status:</span> <span class="badge {certStatus.status === 'valid' ? 'badge-ok' : 'badge-err'}">{certStatus.status}</span></div>
      <div><span class="lbl">Issuer:</span> <code>{certStatus.issuer || 'Self-Signed / Auto'}</code></div>
      <div><span class="lbl">Valid Until:</span> {certStatus.valid_until || 'Indefinite'}</div>
    </div>
    <div style="margin-top:16px">
      <button class="btn-secondary" onclick={renewCert}>Force ACME Renew</button>
    </div>
  </div>
{/if}

<div class="card">
  <h3>Import Custom TLS Certificate</h3>
  <div class="form-group">
    <label for="cert">Certificate PEM</label>
    <textarea id="cert" rows="4" bind:value={certPem} placeholder="-----BEGIN CERTIFICATE-----"></textarea>
  </div>
  <div class="form-group">
    <label for="key">Private Key PEM</label>
    <textarea id="key" rows="4" bind:value={keyPem} placeholder="-----BEGIN PRIVATE KEY-----"></textarea>
  </div>
  <button class="btn-primary" onclick={importCert}>Import Custom Certificate</button>
  {#if importErr}<p class="err-text">{importErr}</p>{/if}
</div>

<style>
  .view-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
  .view-header h2 { margin: 0; font-size: 20px; font-weight: 650; }
  .card { background: #141A24; border: 1px solid rgba(255,255,255,0.08); border-radius: 14px; padding: 20px; margin-bottom: 20px; }
  .card h3 { margin: 0 0 16px; font-size: 14px; text-transform: uppercase; color: rgba(255,255,255,0.7); }
  .form-row { display: flex; gap: 12px; }
  .form-row input { flex: 1; }
  .form-group { margin-bottom: 14px; }
  .form-group label { display: block; font-size: 12px; color: rgba(255,255,255,0.7); margin-bottom: 6px; }
  input, textarea { background: #0F1420; border: 1px solid rgba(255,255,255,0.12); color: #fff; padding: 10px; border-radius: 8px; font: inherit; width: 100%; box-sizing: border-box; }
  .btn-primary { background: #FF7A1A; color: #1a1204; border: none; font-weight: 700; padding: 10px 16px; border-radius: 8px; cursor: pointer; }
  .btn-secondary { background: #1A2230; color: #fff; border: 1px solid rgba(255,255,255,0.1); padding: 10px 16px; border-radius: 8px; cursor: pointer; font-weight: 600; }
  .status-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; font-size: 14px; }
  .lbl { color: rgba(255,255,255,0.6); }
  .badge { padding: 4px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }
  .badge-ok { background: rgba(39,209,124,0.15); color: #27D17C; }
  .badge-err { background: rgba(255,77,77,0.15); color: #FF4D4D; }
  .dns-box { margin-top: 12px; padding: 10px; border-radius: 8px; font-size: 13px; }
  .dns-box.ok { background: rgba(39,209,124,0.15); color: #27D17C; }
  .dns-box.err { background: rgba(255,77,77,0.15); color: #FF4D4D; }
  .err-text { color: #FF4D4D; font-size: 13px; margin-top: 8px; }
</style>
