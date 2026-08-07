<script lang="ts">
  import { onMount } from 'svelte';
  import { apiFetch } from '$lib/api';
  import { showToast } from '$lib/components/Toast.svelte';

  interface AcmeStatus { enabled: boolean; provider: string; email: string; challenge: string; staging: boolean; last_renewal?: string; renewal_error?: string; }
  interface CertInfo { available: boolean; issuer?: string; not_before?: string; not_after?: string; days_remaining?: number; acme: AcmeStatus; }
  interface PanelAddress { domain: string; port: number; admin_path: string; bind_address: string; public_url: string; https_enabled: boolean; server_ipv4: string; server_ipv6: string; cert: CertInfo; }
  interface DnsCheck { domain: string; resolves: boolean; a?: string[]; aaaa?: string[]; server_ipv4?: string; server_ipv6?: string; points_here?: boolean; error?: string; }

  let addr = $state<PanelAddress | null>(null);
  let panelDomain = $state('');
  let loading = $state(true);

  let certPem = $state('');
  let keyPem = $state('');
  let importErr = $state('');

  let dns = $state<DnsCheck | null>(null);
  let checkingDns = $state(false);
  let restartNote = $state(false);

  // The host the admin is currently viewing the panel through. If it isn't the
  // configured domain, the browser is being served the self-signed fallback —
  // which is exactly why a panel opened by IP shows "Not Secure".
  const viewingHost = typeof window !== 'undefined' ? window.location.hostname : '';
  const onDomain = $derived(!!addr?.domain && viewingHost.toLowerCase() === addr.domain.toLowerCase());

  async function loadData() {
    loading = true;
    try {
      addr = await apiFetch<PanelAddress>('/admin/panel-address');
      panelDomain = addr.domain || '';
    } catch (err: any) {
      showToast(err.message || 'Failed to load TLS status', 'error');
    } finally {
      loading = false;
    }
  }

  async function updateDomain() {
    try {
      const res = await apiFetch<{ restart_required: boolean; public_url: string }>('/admin/panel-address', {
        method: 'POST',
        body: JSON.stringify({ domain: panelDomain.trim() })
      });
      restartNote = !!res.restart_required;
      showToast('Panel domain saved — HTTPS/ACME enabled', 'success');
      await loadData();
    } catch (err: any) {
      showToast(err.message || 'Failed to update domain', 'error');
    }
  }

  async function checkDns() {
    if (!panelDomain.trim()) return;
    checkingDns = true;
    dns = null;
    try {
      dns = await apiFetch<DnsCheck>(`/admin/panel-address/dns-check?domain=${encodeURIComponent(panelDomain.trim())}`);
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
      showToast('ACME certificate issued/renewed', 'success');
      await loadData();
    } catch (err: any) {
      showToast(err.message || 'Failed to renew certificate', 'error');
    }
  }

  onMount(() => { loadData(); });
</script>

<div class="view-header">
  <h2>Certificates &amp; Panel Domain</h2>
  <button class="btn-primary" onclick={loadData}>Refresh</button>
</div>

{#if addr?.domain}
  <div class="banner {onDomain ? 'ok' : 'warn'}" data-testid="access-banner">
    {#if onDomain}
      ✅ You are viewing the panel over its domain — this session uses the browser-trusted certificate.
    {:else}
      ⚠️ You are viewing the panel by IP ({viewingHost}), so the browser shows the self-signed fallback and marks it “Not Secure”.
      Open your panel at its domain for a trusted certificate:
      <a class="url" href={addr.public_url} target="_blank" rel="noreferrer">{addr.public_url}</a>
    {/if}
  </div>
{/if}

<div class="card">
  <h3>Panel Domain &amp; Auto TLS (Let's Encrypt / ACME)</h3>
  <p class="hint">Point an A record for your domain at <code>{addr?.server_ipv4 || 'this server'}</code>, save it here, then reopen the panel via the domain. A Let's Encrypt certificate is issued automatically.</p>
  <div class="form-row">
    <input type="text" bind:value={panelDomain} placeholder="panel.example.com" data-testid="domain-input" />
    <button class="btn-primary" onclick={updateDomain} data-testid="save-domain">Save Domain</button>
    <button class="btn-secondary" onclick={checkDns} disabled={checkingDns} data-testid="check-dns">
      {checkingDns ? 'Checking...' : 'Check DNS'}
    </button>
  </div>

  {#if restartNote}
    <div class="dns-box warn">Saved. A restart applies the change to the ACME helper — <code>docker compose restart forgepanel</code> (or restart the service).</div>
  {/if}

  {#if dns}
    {#if !dns.resolves}
      <div class="dns-box err" data-testid="dns-result">DNS records failed to resolve{dns.error ? ` (${dns.error})` : ''}.</div>
    {:else if dns.points_here}
      <div class="dns-box ok" data-testid="dns-result">DNS resolves to {(dns.a || []).join(', ')} — points at this server ✅</div>
    {:else}
      <div class="dns-box warn" data-testid="dns-result">DNS resolves to {(dns.a || []).join(', ')}, but this server is {dns.server_ipv4}. Update the A record to point here.</div>
    {/if}
  {/if}
</div>

{#if addr}
  <div class="card">
    <h3>Active TLS Certificate Status</h3>
    <div class="status-grid">
      <div><span class="lbl">Domain:</span> <strong>{addr.domain || 'N/A (self-signed on IP)'}</strong></div>
      <div>
        <span class="lbl">Status:</span>
        {#if addr.cert?.available}
          <span class="badge badge-ok" data-testid="cert-status">Trusted (ACME)</span>
        {:else if addr.domain}
          <span class="badge badge-warn" data-testid="cert-status">Pending issuance</span>
        {:else}
          <span class="badge badge-err" data-testid="cert-status">Self-signed</span>
        {/if}
      </div>
      <div><span class="lbl">Issuer:</span> <code>{addr.cert?.issuer || 'Self-Signed'}</code></div>
      <div><span class="lbl">Valid Until:</span> {addr.cert?.not_after ? new Date(addr.cert.not_after).toLocaleDateString() : 'Indefinite'}{addr.cert?.days_remaining != null ? ` (${addr.cert.days_remaining}d)` : ''}</div>
    </div>
    {#if addr.cert?.acme?.renewal_error}
      <div class="dns-box err">Last ACME error: {addr.cert.acme.renewal_error}</div>
    {/if}
    <div style="margin-top:16px">
      <button class="btn-secondary" onclick={renewCert} data-testid="renew-cert">Force ACME Issue / Renew</button>
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
  .hint { font-size: 13px; color: rgba(255,255,255,0.6); margin: 0 0 14px; }
  .banner { border-radius: 12px; padding: 14px 16px; margin-bottom: 20px; font-size: 14px; line-height: 1.5; }
  .banner.ok { background: rgba(39,209,124,0.12); border: 1px solid rgba(39,209,124,0.3); color: #27D17C; }
  .banner.warn { background: rgba(255,176,32,0.1); border: 1px solid rgba(255,176,32,0.3); color: #FFC24B; }
  .banner .url { display: inline-block; margin-top: 6px; color: #FF9B4A; font-weight: 700; word-break: break-all; }
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
  .badge-warn { background: rgba(255,176,32,0.15); color: #FFC24B; }
  .badge-err { background: rgba(255,77,77,0.15); color: #FF4D4D; }
  .dns-box { margin-top: 12px; padding: 10px; border-radius: 8px; font-size: 13px; }
  .dns-box.ok { background: rgba(39,209,124,0.15); color: #27D17C; }
  .dns-box.warn { background: rgba(255,176,32,0.12); color: #FFC24B; }
  .dns-box.err { background: rgba(255,77,77,0.15); color: #FF4D4D; }
  .err-text { color: #FF4D4D; font-size: 13px; margin-top: 8px; }
</style>
