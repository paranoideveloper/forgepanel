<script lang="ts">
	import { tr } from '$lib/i18n';
  import { onMount } from 'svelte';
  import { apiFetch } from '$lib/api';
  import QRCode from '$lib/components/QRCode.svelte';
  import { showToast } from '$lib/components/Toast.svelte';

  // A guided, BPB/Nova-style onboarding: domain+TLS → first inbound → first user
  // → share. Every step reuses the panel's existing endpoints, so it just
  // orchestrates the flow a new operator would otherwise have to discover.
  let step = $state(1);
  const steps = ['Domain & TLS', 'First inbound', 'First user', 'Share'];

  // step 1
  let domain = $state('');
  let serverIP = $state('');
  let certAvailable = $state(false);
  let savingDomain = $state(false);

  // step 2
  let inboundCreated = $state(false);
  let inboundInfo = $state('');
  let creatingInbound = $state(false);

  // step 3
  let username = $state('');
  let limitGB = $state(0);
  let expireDays = $state(0);
  let creatingUser = $state(false);
  let subToken = $state('');

  const subBase = $derived(subToken ? `${window.location.origin}/sub/${subToken}` : '');
  const viewingHost = typeof window !== 'undefined' ? window.location.hostname : '';

  async function loadAddr() {
    try {
      const a = await apiFetch<{ domain: string; server_ipv4: string; cert: { available: boolean } }>('/admin/panel-address');
      domain = a.domain || '';
      serverIP = a.server_ipv4 || '';
      certAvailable = !!a.cert?.available;
    } catch (_) {}
  }
  onMount(loadAddr);

  async function saveDomain(skip = false) {
    if (skip) { step = 2; return; }
    if (!domain.trim()) { showToast(tr('setupwizard.enter_a_domain_or_skip_to'), 'error'); return; }
    savingDomain = true;
    try {
      await apiFetch('/admin/panel-address', { method: 'POST', body: JSON.stringify({ domain: domain.trim() }) });
      await loadAddr();
      showToast(tr('setupwizard.domain_saved_https_acme_enabled'), 'success');
      step = 2;
    } catch (e: any) {
      showToast(e.message || tr('setupwizard.failed_to_save_domain'), 'error');
    } finally {
      savingDomain = false;
    }
  }

  async function createInbound() {
    creatingInbound = true;
    try {
      const r = await apiFetch<any>('/admin/inbounds/reality-quickstart', { method: 'POST', body: JSON.stringify({}) });
      inboundCreated = true;
      inboundInfo = r?.node?.remark || r?.remark || tr('setupwizard.vless_reality');
      showToast(tr('setupwizard.inbound_created_vless_reality'), 'success');
    } catch (e: any) {
      showToast(e.message || tr('setupwizard.failed_to_create_inbound'), 'error');
    } finally {
      creatingInbound = false;
    }
  }

  async function createUser() {
    if (!username.trim()) { showToast(tr('setupwizard.enter_a_username'), 'error'); return; }
    creatingUser = true;
    try {
      const u = await apiFetch<any>('/admin/users', {
        method: 'POST',
        body: JSON.stringify({ username: username.trim(), data_limit_gb: limitGB || 0, expire_days: expireDays || 0 })
      });
      subToken = u?.sub_token || u?.subToken || '';
      // A user needs at least one inbound to have a working subscription; the
      // quickstart inbound is unassigned by default, so bind every inbound to this
      // first user so their link works immediately.
      try {
        const inbounds = await apiFetch<Array<{ id: number }>>('/admin/inbounds');
        if (u?.id && inbounds.length) {
          await apiFetch(`/admin/users/${u.id}/inbounds`, { method: 'PUT', body: JSON.stringify({ inbound_ids: inbounds.map((i) => i.id) }) });
        }
      } catch (_) {}
      showToast(tr('setupwizard.user_created'), 'success');
      step = 4;
    } catch (e: any) {
      showToast(e.message || tr('setupwizard.failed_to_create_user'), 'error');
    } finally {
      creatingUser = false;
    }
  }

  async function copy(text: string) {
    try { await navigator.clipboard.writeText(text); showToast(tr('setupwizard.copied'), 'success'); }
    catch (_) { showToast(tr('setupwizard.copy_failed'), 'error'); }
  }

  // One-click Preset Wizard: build the WHOLE multi-protocol server (every config
  // family, keys/ports/firewall/DNS wired) from a domain + a Cloudflare token.
  let pwDomain = $state('');
  let pwToken = $state('');
  let pwAccount = $state('');
  let pwRunning = $state(false);
  let pwResult = $state<any>(null);

  async function runPresetWizard() {
    pwRunning = true;
    pwResult = null;
    try {
      const r = await apiFetch<any>('/admin/wizard/preset', {
        method: 'POST',
        body: JSON.stringify({ domain: pwDomain.trim(), cf_token: pwToken.trim(), cf_account_id: pwAccount.trim() })
      });
      pwResult = r;
      showToast(tr('setupwizard.built_count_inbounds', { count: r.count }), 'success');
    } catch (e: any) {
      showToast(e.message || tr('setupwizard.preset_wizard_failed'), 'error');
    } finally {
      pwRunning = false;
    }
  }
</script>

<div class="view-header"><h2>{tr('setupwizard.setup_wizard')}</h2></div>

<div class="card preset">
  <h3>{tr('setupwizard.one_click_full_server_preset_wizard')}</h3>
  <p class="hint">{tr('setupwizard.build_the_whole_multi_protocol_server')}</p>
  <div class="row">
    <input placeholder={tr('setupwizard.domain_for_the_cdn_configs_e')} bind:value={pwDomain} data-testid="pw-domain" />
    <input placeholder={tr('setupwizard.cloudflare_api_token_optional_auto_creates')} bind:value={pwToken} data-testid="pw-token" />
    <button class="primary" onclick={runPresetWizard} disabled={pwRunning} data-testid="pw-run">{pwRunning ? tr('setupwizard.building') : tr('setupwizard.build_full_server')}</button>
  </div>
  <p class="tiny">{tr('setupwizard.token_needs')} <strong>{tr('setupwizard.zone_dns_edit')}</strong> {tr('setupwizard.for_the_domain_without_it_the')}</p>
  {#if pwResult}
    <div class="pw-result">
      <p class="ok-line">{tr('setupwizard.created_inbounds_reality_key', { count: pwResult.count })} <code>{pwResult.reality?.public_key}</code></p>
      <ul class="pw-list">
        {#each pwResult.created as c}<li>{tr('setupwizard.port', { remark: c.remark, port: c.port, p3: c.cdn ? tr('setupwizard.behind_cloudflare') : tr('setupwizard.direct') })}</li>{/each}
      </ul>
      {#if pwResult.warnings?.length}{#each pwResult.warnings as w}<p class="warn-line">⚠️ {w}</p>{/each}{/if}
    </div>
  {/if}
</div>

<div class="stepper">
  {#each steps as label, i}
    <div class="stepitem {step === i + 1 ? 'active' : step > i + 1 ? 'done' : ''}">
      <span class="num">{step > i + 1 ? '✓' : i + 1}</span><span class="lbl">{label}</span>
    </div>
  {/each}
</div>

<div class="card">
  {#if step === 1}
    <h3>{tr('setupwizard.1_domain_amp_automatic_tls')}</h3>
    <p class="hint">{tr('setupwizard.point_a_domain_s_a_record')} <code>{serverIP || tr('setupwizard.this_server')}</code>{tr('setupwizard.then_save_it_here_to_get')}</p>
    <div class="row">
      <input placeholder={tr('setupwizard.panel_example_com')} bind:value={domain} data-testid="wiz-domain" />
      <button class="primary" onclick={() => saveDomain(false)} disabled={savingDomain} data-testid="wiz-save-domain">{savingDomain ? tr('setupwizard.saving') : tr('setupwizard.save_continue')}</button>
      <button class="ghost" onclick={() => saveDomain(true)} data-testid="wiz-skip-domain">{tr('setupwizard.skip')}</button>
    </div>
    {#if domain && certAvailable}<p class="ok-line">{tr('setupwizard.a_trusted_certificate_is_active_for', { domain })}</p>{/if}
  {:else if step === 2}
    <h3>{tr('setupwizard.2_create_your_first_inbound')}</h3>
    <p class="hint">{tr('setupwizard.vless_reality_is_the_most_censorship')}</p>
    {#if !inboundCreated}
      <button class="primary" onclick={createInbound} disabled={creatingInbound} data-testid="wiz-create-inbound">{creatingInbound ? tr('setupwizard.creating') : tr('setupwizard.create_vless_reality')}</button>
    {:else}
      <p class="ok-line">{tr('setupwizard.created')} <strong>{inboundInfo}</strong></p>
    {/if}
    <div class="nav">
      <button class="ghost" onclick={() => (step = 1)}>{tr('setupwizard.back')}</button>
      <button class="primary" onclick={() => (step = 3)} disabled={!inboundCreated} data-testid="wiz-next-user">{tr('setupwizard.next')}</button>
    </div>
  {:else if step === 3}
    <h3>{tr('setupwizard.3_create_your_first_user')}</h3>
    <p class="hint">{tr('setupwizard.a_user_gets_a_private_subscription')}</p>
    <div class="row">
      <input placeholder={tr('setupwizard.username')} bind:value={username} data-testid="wiz-username" />
      <input type="number" placeholder={tr('setupwizard.limit_gb_0')} bind:value={limitGB} />
      <input type="number" placeholder={tr('setupwizard.expire_days_0_never')} bind:value={expireDays} />
    </div>
    <div class="nav">
      <button class="ghost" onclick={() => (step = 2)}>{tr('setupwizard.back')}</button>
      <button class="primary" onclick={createUser} disabled={creatingUser} data-testid="wiz-create-user">{creatingUser ? tr('setupwizard.creating') : tr('setupwizard.create_user')}</button>
    </div>
  {:else}
    <h3>{tr('setupwizard.4_share_the_subscription')}</h3>
    <p class="hint">{tr('setupwizard.send_this_link_to_the_user')}</p>
    {#if subBase}
      <div class="share">
        <div class="qr"><QRCode value={subBase} size={180} /></div>
        <div class="links">
          <div class="linkrow"><code>{subBase}</code><button class="ghost sm" onclick={() => copy(subBase)} data-testid="wiz-copy-sub">{tr('setupwizard.copy')}</button></div>
          <a class="ghost sm openbtn" href={subBase} target="_blank" rel="noreferrer">{tr('setupwizard.open_subscription_page')}</a>
          <p class="tiny">{tr('setupwizard.clients_hiddify_v2rayng_nekobox_sing_box')} <strong>{tr('setupwizard.users_amp_subscriptions_subscription_defaults')}</strong>.</p>
        </div>
      </div>
      {#if !domain}<p class="warn-line">{tr('setupwizard.you_re_on_the_ip_with')}</p>{/if}
    {/if}
    <div class="nav"><button class="ghost" onclick={() => (step = 3)}>{tr('setupwizard.back')}</button><button class="primary" onclick={() => (step = 1)}>{tr('setupwizard.done_start_over')}</button></div>
  {/if}
</div>

<style>
  .view-header h2 { margin: 0 0 20px; font-size: 20px; }
  .card { background: var(--card); border: 1px solid var(--ln-3); border-radius: 14px; padding: 22px; }
  .card h3 { margin: 0 0 10px; font-size: 16px; }
  .hint { color: var(--t-5); font-size: 13px; margin: 0 0 16px; line-height: 1.5; }
  .stepper { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 18px; }
  .stepitem { display: flex; align-items: center; gap: 8px; padding: 8px 12px; border-radius: 10px; background: var(--bg); border: 1px solid var(--ln-3); font-size: 13px; color: var(--t-6); }
  .stepitem.active { border-color: rgba(255,122,26,0.5); color: var(--acc-2); }
  .stepitem.done { color: var(--ok); }
  .stepitem .num { width: 22px; height: 22px; border-radius: 50%; background: var(--ln-3); display: inline-flex; align-items: center; justify-content: center; font-weight: 700; font-size: 12px; }
  .stepitem.active .num { background: var(--acc); color: var(--acc-soft); }
  .stepitem.done .num { background: rgba(39,209,124,0.2); color: var(--ok); }
  .row { display: flex; gap: 10px; flex-wrap: wrap; }
  .row input { flex: 1; min-width: 160px; }
  input { background: var(--bg); border: 1px solid var(--ln-5); color: var(--fg); padding: 10px; border-radius: 8px; font: inherit; box-sizing: border-box; }
  .primary { background: var(--acc); color: var(--acc-soft); border: none; font-weight: 700; padding: 10px 16px; border-radius: 8px; cursor: pointer; white-space: nowrap; }
  .primary:disabled { opacity: 0.5; cursor: default; }
  .ghost { background: var(--raised); color: var(--fg); border: 1px solid var(--ln-4); padding: 10px 16px; border-radius: 8px; cursor: pointer; font-weight: 600; }
  .ghost.sm { padding: 6px 12px; font-size: 12px; }
  .nav { display: flex; justify-content: space-between; margin-top: 18px; gap: 10px; }
  .preset { margin-bottom: 18px; border-color: rgba(255,122,26,0.35); }
  .pw-result { margin-top: 14px; }
  .pw-list { margin: 8px 0 0; padding-inline-start: 18px; color: var(--t-2); font-size: 13px; line-height: 1.7; }
  .pw-list li { word-break: break-word; }
  .ok-line { color: var(--ok); font-size: 14px; margin-top: 14px; }
  .warn-line { color: var(--warn-2); font-size: 13px; margin-top: 14px; }
  .share { display: flex; gap: 20px; flex-wrap: wrap; align-items: flex-start; }
  .qr { background: #fff; padding: 10px; border-radius: 10px; }
  .links { flex: 1; min-width: 240px; display: flex; flex-direction: column; gap: 10px; }
  .linkrow { display: flex; gap: 8px; align-items: center; }
  .linkrow code { background: var(--bg); padding: 8px 10px; border-radius: 8px; font-size: 12px; word-break: break-all; flex: 1; }
  .openbtn { display: inline-block; width: fit-content; text-decoration: none; }
  .tiny { font-size: 12px; color: var(--t-7); line-height: 1.5; margin: 4px 0 0; }
  code { background: var(--bg); padding: 2px 6px; border-radius: 6px; }
  @media (max-width: 768px) {
    .row { flex-direction: column; }
    .row input, .row .primary, .row .ghost { width: 100%; }
    .share { flex-direction: column; }
  }
</style>
