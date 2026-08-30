<script lang="ts">
	import { tr } from '$lib/i18n';
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

  // The panel's listener.
  //
  // POST /admin/panel-address has always accepted domain, port, bind_address,
  // https_enabled, acme_email and verify_dns, and this view posted {domain}. GET
  // has always returned port, bind_address, admin_path, https_enabled and
  // server_ipv6, and none of them was rendered. So the panel's own port and bind
  // address could only be changed by editing panel.json by hand and restarting —
  // on the one surface whose whole subject is where the panel lives.
  let panelPort = $state(0);
  let bindAddress = $state('');
  let httpsEnabled = $state(false);
  let acmeEmail = $state('');
  let verifyDns = $state(false);
  let savingAddr = $state(false);
  let addrErr = $state('');

  // Port pre-flight. GET /admin/panel-address/port-check answers
  // {port, available, current} and had no caller, so the first time anyone
  // learned the port was taken was after the save, from a bare 400.
  let portCheck = $state<{ port: number; available: boolean; current: boolean } | null>(null);
  let checkingPort = $state(false);

  // The server's rules, mirrored so a typo is caught before it becomes a 400
  // with no hint about what the rule is. Server-side validation stays the
  // authority; this only explains it earlier.
  const DOMAIN_RE = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
  const normalizedDomain = $derived(panelDomain.trim().toLowerCase().replace(/\.$/, ''));
  const domainInvalid = $derived(normalizedDomain !== '' && !DOMAIN_RE.test(normalizedDomain));
  const portInvalid = $derived(!Number.isInteger(panelPort) || panelPort < 1 || panelPort > 65535);
  const bindInvalid = $derived(bindAddress.trim() !== '' && !isIP(bindAddress.trim()));
  const httpsWithoutDomain = $derived(httpsEnabled && normalizedDomain === '');
  const emailInvalid = $derived(
    acmeEmail.trim() !== '' && !/^[^\s@]+@([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(acmeEmail.trim())
  );
  const addressFormBlocked = $derived(domainInvalid || portInvalid || bindInvalid || httpsWithoutDomain || emailInvalid);

  function isIP(v: string): boolean {
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(v)) return v.split('.').every((o) => Number(o) <= 255);
    return /^[0-9a-f:]+$/i.test(v) && v.includes(':');
  }

  async function checkPort() {
    if (portInvalid) return;
    checkingPort = true;
    portCheck = null;
    try {
      portCheck = await apiFetch(`/admin/panel-address/port-check?port=${panelPort}`);
    } catch (err: any) {
      showToast(err.message || tr('certificates.port_check_failed'), 'error');
    } finally {
      checkingPort = false;
    }
  }

  async function saveAddress() {
    addrErr = '';
    savingAddr = true;
    try {
      const res = await apiFetch<{ restart_required: boolean; public_url: string }>('/admin/panel-address', {
        method: 'POST',
        body: JSON.stringify({
          domain: normalizedDomain,
          port: panelPort,
          bind_address: bindAddress.trim(),
          https_enabled: httpsEnabled,
          acme_email: acmeEmail.trim(),
          verify_dns: verifyDns
        })
      });
      restartNote = !!res.restart_required;
      showToast(tr('certificates.panel_address_saved'), 'success');
      await loadData();
    } catch (err: any) {
      addrErr = err.message || tr('certificates.failed_to_update_domain');
    } finally {
      savingAddr = false;
    }
  }

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
      panelPort = addr.port ?? 0;
      bindAddress = addr.bind_address || '';
      httpsEnabled = !!addr.https_enabled;
      acmeEmail = addr.cert?.acme?.email || '';
      portCheck = null;
    } catch (err: any) {
      showToast(err.message || tr('certificates.failed_to_load_tls_status'), 'error');
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
      showToast(tr('certificates.panel_domain_saved_https_acme_enabled'), 'success');
      await loadData();
    } catch (err: any) {
      showToast(err.message || tr('certificates.failed_to_update_domain'), 'error');
    }
  }

  async function checkDns() {
    if (!panelDomain.trim()) return;
    checkingDns = true;
    dns = null;
    try {
      dns = await apiFetch<DnsCheck>(`/admin/panel-address/dns-check?domain=${encodeURIComponent(panelDomain.trim())}`);
    } catch (err: any) {
      showToast(tr('certificates.dns_check_failed'), 'error');
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
        // handleCertImport binds {cert,key}; cert_pem/key_pem arrived empty and
        // X509KeyPair failed every time, so no certificate could be imported.
        body: JSON.stringify({ cert: certPem.trim(), key: keyPem.trim() })
      });
      certPem = '';
      keyPem = '';
      showToast(tr('certificates.tls_certificate_imported_successfully'), 'success');
      await loadData();
    } catch (err: any) {
      importErr = err.message || 'Failed to import certificate';
    }
  }

  async function renewCert() {
    try {
      await apiFetch('/admin/panel-address/cert/renew', { method: 'POST' });
      showToast(tr('certificates.acme_certificate_issued_renewed'), 'success');
      await loadData();
    } catch (err: any) {
      showToast(err.message || tr('certificates.failed_to_renew_certificate'), 'error');
    }
  }

  onMount(() => { loadData(); });
</script>

<div class="view-header">
  <h2>{tr('certificates.certificates_amp_panel_domain')}</h2>
  <button class="btn-primary" onclick={loadData}>{tr('certificates.refresh')}</button>
</div>

{#if addr?.domain}
  <div class="banner {onDomain && addr.cert?.available ? 'ok' : 'warn'}" data-testid="access-banner">
    {#if onDomain && addr.cert?.available}
      {tr('certificates.you_are_viewing_the_panel_over', {  })}
    {:else if onDomain}
      {tr('certificates.you_are_on_the_domain_but', {  })} <strong>{tr('certificates.force_acme_issue_renew')}</strong> {tr('certificates.below_if_it_keeps_failing_let')} <strong>{tr('certificates.port_80')}</strong> {tr('certificates.of_this_server_from_the_internet')} <code>80:80</code>{tr('certificates.a_domain_saved_after_startup_also', {  })}
    {:else}
      {tr('certificates.you_are_viewing_the_panel_by', { viewingHost })}
      <a class="url" href={addr.public_url} target="_blank" rel="noreferrer">{addr.public_url}</a>
    {/if}
  </div>
{/if}

<div class="card">
  <h3>{tr('certificates.panel_domain_amp_auto_tls_let')}</h3>
  <p class="hint">{tr('certificates.point_an_a_record_for_your')} <code>{addr?.server_ipv4 || tr('certificates.this_server')}</code>{tr('certificates.save_it_here_then_reopen_the')} <strong>{tr('certificates.port_80')}</strong> {tr('certificates.reachable_from_the_internet_open_it')} <code>80:80</code>).</p>
  <div class="form-row">
    <input type="text" bind:value={panelDomain} placeholder={tr('certificates.panel_example_com')} data-testid="domain-input" />
    <button class="btn-primary" onclick={updateDomain} data-testid="save-domain">{tr('certificates.save_domain')}</button>
    <button class="btn-secondary" onclick={checkDns} disabled={checkingDns} data-testid="check-dns">
      {checkingDns ? tr('certificates.checking') : tr('certificates.check_dns')}
    </button>
  </div>
  {#if domainInvalid}
    <p class="err-text" data-testid="domain-invalid">{tr('certificates.domain_rule')}</p>
  {/if}

  {#if restartNote}
    <div class="dns-box warn">{tr('certificates.saved_a_restart_applies_the_change')} <code>{tr('certificates.docker_compose_restart_forgepanel')}</code> {tr('certificates.or_restart_the_service')}</div>
  {/if}

  {#if dns}
    {#if !dns.resolves}
      <div class="dns-box err" data-testid="dns-result">{tr('certificates.dns_records_failed_to_resolve', { p1: dns.error ? ` (${dns.error})` : '' })}</div>
    {:else if dns.points_here}
      <div class="dns-box ok" data-testid="dns-result">{tr('certificates.dns_resolves_to_points_at_this', { p1: (dns.a || []).join(', ') })}</div>
    {:else}
      <div class="dns-box warn" data-testid="dns-result">{tr('certificates.dns_resolves_to_but_this_server', { p1: (dns.a || []).join(', '), server_ipv4: dns.server_ipv4 })}</div>
    {/if}
  {/if}
</div>

{#if addr}
  <div class="card" data-testid="panel-listener">
    <h3>{tr('certificates.where_the_panel_listens')}</h3>
    <p class="hint">{tr('certificates.listener_hint')}</p>

    <div class="status-grid">
      <div><span class="lbl">{tr('certificates.public_url')}</span> <code data-testid="public-url">{addr.public_url}</code></div>
      <div><span class="lbl">{tr('certificates.admin_path')}</span> <code data-testid="admin-path">{addr.admin_path}</code></div>
      <div><span class="lbl">{tr('certificates.server_ipv4')}</span> <code>{addr.server_ipv4 || tr('certificates.unknown')}</code></div>
      <div><span class="lbl">{tr('certificates.server_ipv6')}</span> <code data-testid="server-ipv6">{addr.server_ipv6 || tr('certificates.none')}</code></div>
    </div>

    <div class="form-row">
      <label class="fl">{tr('certificates.port')}
        <input type="number" bind:value={panelPort} data-testid="port-input" min="1" max="65535" />
      </label>
      <button class="btn-secondary" onclick={checkPort} disabled={checkingPort || portInvalid} data-testid="check-port">
        {checkingPort ? tr('certificates.checking') : tr('certificates.check_port')}
      </button>
      <label class="fl">{tr('certificates.bind_address')}
        <input type="text" bind:value={bindAddress} placeholder="0.0.0.0" data-testid="bind-input" />
      </label>
    </div>
    {#if portInvalid}
      <p class="err-text" data-testid="port-invalid">{tr('certificates.port_rule')}</p>
    {/if}
    {#if bindInvalid}
      <p class="err-text" data-testid="bind-invalid">{tr('certificates.bind_rule')}</p>
    {/if}
    {#if portCheck}
      {#if portCheck.current}
        <div class="dns-box ok" data-testid="port-result">{tr('certificates.port_is_the_current_one', { port: portCheck.port })}</div>
      {:else if portCheck.available}
        <div class="dns-box ok" data-testid="port-result">{tr('certificates.port_is_free', { port: portCheck.port })}</div>
      {:else}
        <div class="dns-box err" data-testid="port-result">{tr('certificates.port_is_taken', { port: portCheck.port })}</div>
      {/if}
    {/if}

    <div class="form-row">
      <label class="chk"><input type="checkbox" bind:checked={httpsEnabled} data-testid="https-toggle" /> {tr('certificates.serve_https_acme')}</label>
      <label class="fl">{tr('certificates.acme_email')}
        <input type="text" bind:value={acmeEmail} placeholder={tr('certificates.acme_email_placeholder')} data-testid="acme-email" />
      </label>
      <label class="chk"><input type="checkbox" bind:checked={verifyDns} data-testid="verify-dns" /> {tr('certificates.verify_dns_before_saving')}</label>
    </div>
    {#if httpsWithoutDomain}
      <p class="err-text" data-testid="https-needs-domain">{tr('certificates.https_needs_a_domain')}</p>
    {/if}
    {#if emailInvalid}
      <p class="err-text" data-testid="email-invalid">{tr('certificates.email_rule')}</p>
    {/if}

    <div style="margin-top:16px">
      <button class="btn-primary" onclick={saveAddress} disabled={savingAddr || addressFormBlocked} data-testid="save-address">
        {savingAddr ? tr('certificates.saving') : tr('certificates.save_listener')}
      </button>
    </div>
    {#if addrErr}<p class="err-text" data-testid="address-error">{addrErr}</p>{/if}
  </div>

  <div class="card">
    <h3>{tr('certificates.active_tls_certificate_status')}</h3>
    <div class="status-grid">
      <div><span class="lbl">{tr('certificates.domain')}</span> <strong>{addr.domain || tr('certificates.n_a_self_signed_on_ip')}</strong></div>
      <div>
        <span class="lbl">{tr('certificates.status')}</span>
        {#if addr.cert?.available}
          <span class="badge badge-ok" data-testid="cert-status">{tr('certificates.trusted_acme')}</span>
        {:else if addr.domain}
          <span class="badge badge-warn" data-testid="cert-status">{tr('certificates.pending_issuance')}</span>
        {:else}
          <span class="badge badge-err" data-testid="cert-status">{tr('certificates.self_signed')}</span>
        {/if}
      </div>
      <div><span class="lbl">{tr('certificates.issuer')}</span> <code>{addr.cert?.issuer || tr('certificates.self_signed_2')}</code></div>
      <div><span class="lbl">{tr('certificates.valid_until')}</span> {addr.cert?.not_after ? new Date(addr.cert.not_after).toLocaleDateString() : tr('certificates.indefinite')}{addr.cert?.days_remaining != null ? ` (${addr.cert.days_remaining}d)` : ''}</div>
    </div>
    {#if addr.cert?.acme?.renewal_error}
      <div class="dns-box err">{tr('certificates.last_acme_error', { renewal_error: addr.cert.acme.renewal_error })}</div>
    {/if}
    <div style="margin-top:16px">
      <button class="btn-secondary" onclick={renewCert} data-testid="renew-cert">{tr('certificates.force_acme_issue_renew')}</button>
    </div>
  </div>
{/if}

<div class="card">
  <h3>{tr('certificates.import_custom_tls_certificate')}</h3>
  <div class="form-group">
    <label for="cert">{tr('certificates.certificate_pem')}</label>
    <textarea id="cert" rows="4" bind:value={certPem} placeholder={tr('certificates.begin_certificate')}></textarea>
  </div>
  <div class="form-group">
    <label for="key">{tr('certificates.private_key_pem')}</label>
    <textarea id="key" rows="4" bind:value={keyPem} placeholder={tr('certificates.begin_private_key')}></textarea>
  </div>
  <button class="btn-primary" onclick={importCert}>{tr('certificates.import_custom_certificate')}</button>
  {#if importErr}<p class="err-text">{importErr}</p>{/if}
</div>

<style>
  .view-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
  .view-header h2 { margin: 0; font-size: 20px; font-weight: 650; }
  .card { background: var(--card); border: 1px solid var(--ln-3); border-radius: 14px; padding: 20px; margin-bottom: 20px; }
  .card h3 { margin: 0 0 16px; font-size: 14px; text-transform: uppercase; color: var(--t-3); }
  .hint { font-size: 13px; color: var(--t-5); margin: 0 0 14px; }
  .banner { border-radius: 12px; padding: 14px 16px; margin-bottom: 20px; font-size: 14px; line-height: 1.5; }
  .banner.ok { background: rgba(39,209,124,0.12); border: 1px solid rgba(39,209,124,0.3); color: var(--ok); }
  .banner.warn { background: rgba(255,176,32,0.1); border: 1px solid rgba(255,176,32,0.3); color: var(--warn-2); }
  .banner .url { display: inline-block; margin-top: 6px; color: var(--acc-2); font-weight: 700; word-break: break-all; }
  .form-row { display: flex; gap: 12px; }
  .form-row input { flex: 1; }
  .form-group { margin-bottom: 14px; }
  .form-group label { display: block; font-size: 12px; color: var(--t-3); margin-bottom: 6px; }
  input, textarea { background: var(--bg); border: 1px solid var(--ln-5); color: var(--fg); padding: 10px; border-radius: 8px; font: inherit; width: 100%; box-sizing: border-box; }
  .btn-primary { background: var(--acc); color: var(--acc-soft); border: none; font-weight: 700; padding: 10px 16px; border-radius: 8px; cursor: pointer; }
  .btn-secondary { background: var(--raised); color: var(--fg); border: 1px solid var(--ln-4); padding: 10px 16px; border-radius: 8px; cursor: pointer; font-weight: 600; }
  .status-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; font-size: 14px; }
  .lbl { color: var(--t-5); }
  .badge { padding: 4px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }
  .badge-ok { background: rgba(39,209,124,0.15); color: var(--ok); }
  .badge-warn { background: rgba(255,176,32,0.15); color: var(--warn-2); }
  .badge-err { background: rgba(255,77,77,0.15); color: var(--bad); }
  .dns-box { margin-top: 12px; padding: 10px; border-radius: 8px; font-size: 13px; }
  .dns-box.ok { background: rgba(39,209,124,0.15); color: var(--ok); }
  .dns-box.warn { background: rgba(255,176,32,0.12); color: var(--warn-2); }
  .dns-box.err { background: rgba(255,77,77,0.15); color: var(--bad); }
  .err-text { color: var(--bad); font-size: 13px; margin-top: 8px; }
  .fl { display: flex; flex-direction: column; gap: 4px; font-size: 12px; color: var(--t-5); }
  .fl input { min-width: 120px; }
  .chk { display: flex; align-items: center; gap: 6px; font-size: 13px; }
</style>
