<script lang="ts">
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
    if (!domain.trim()) { showToast('Enter a domain, or Skip to use the IP', 'error'); return; }
    savingDomain = true;
    try {
      await apiFetch('/admin/panel-address', { method: 'POST', body: JSON.stringify({ domain: domain.trim() }) });
      await loadAddr();
      showToast('Domain saved — HTTPS/ACME enabled', 'success');
      step = 2;
    } catch (e: any) {
      showToast(e.message || 'Failed to save domain', 'error');
    } finally {
      savingDomain = false;
    }
  }

  async function createInbound() {
    creatingInbound = true;
    try {
      const r = await apiFetch<any>('/admin/inbounds/reality-quickstart', { method: 'POST', body: JSON.stringify({}) });
      inboundCreated = true;
      inboundInfo = r?.node?.remark || r?.remark || 'VLESS + REALITY';
      showToast('Inbound created (VLESS + REALITY)', 'success');
    } catch (e: any) {
      showToast(e.message || 'Failed to create inbound', 'error');
    } finally {
      creatingInbound = false;
    }
  }

  async function createUser() {
    if (!username.trim()) { showToast('Enter a username', 'error'); return; }
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
      showToast('User created', 'success');
      step = 4;
    } catch (e: any) {
      showToast(e.message || 'Failed to create user', 'error');
    } finally {
      creatingUser = false;
    }
  }

  async function copy(text: string) {
    try { await navigator.clipboard.writeText(text); showToast('Copied', 'success'); }
    catch (_) { showToast('Copy failed', 'error'); }
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
      showToast(`Built ${r.count} inbounds`, 'success');
    } catch (e: any) {
      showToast(e.message || 'Preset wizard failed', 'error');
    } finally {
      pwRunning = false;
    }
  }
</script>

<div class="view-header"><h2>Setup Wizard</h2></div>

<div class="card preset">
  <h3>🧙 One-click full server (Preset Wizard)</h3>
  <p class="hint">Build the whole multi-protocol server in a single step — REALITY-Vision, REALITY-XHTTP &amp; Brutal (direct, SNI-rotating), VLESS-WS / VLESS-XHTTP / VMess-WS over TLS behind Cloudflare, and Shadowsocks-2022. Keys, ports, firewall and the Cloudflare DNS record are all wired for you. Then just create a user below and share.</p>
  <div class="row">
    <input placeholder="domain for the CDN configs (e.g. anonymous.observer)" bind:value={pwDomain} data-testid="pw-domain" />
    <input placeholder="Cloudflare API token (optional — auto-creates DNS)" bind:value={pwToken} data-testid="pw-token" />
    <button class="primary" onclick={runPresetWizard} disabled={pwRunning} data-testid="pw-run">{pwRunning ? 'Building…' : '⚡ Build full server'}</button>
  </div>
  <p class="tiny">Token needs <strong>Zone · DNS · Edit</strong> for the domain. Without it the wizard still builds everything and tells you the single A-record to add. REALITY needs no domain at all.</p>
  {#if pwResult}
    <div class="pw-result">
      <p class="ok-line">✅ Created {pwResult.count} inbounds · REALITY key <code>{pwResult.reality?.public_key}</code></p>
      <ul class="pw-list">
        {#each pwResult.created as c}<li>{c.remark} · port {c.port}{c.cdn ? ' · behind Cloudflare' : ' · direct'}</li>{/each}
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
    <h3>1 · Domain &amp; automatic TLS</h3>
    <p class="hint">Point a domain's A record at <code>{serverIP || 'this server'}</code>, then save it here to get a free Let's Encrypt certificate. Needs port 80 reachable. No domain? Skip — the panel stays on a self-signed cert at the IP.</p>
    <div class="row">
      <input placeholder="panel.example.com" bind:value={domain} data-testid="wiz-domain" />
      <button class="primary" onclick={() => saveDomain(false)} disabled={savingDomain} data-testid="wiz-save-domain">{savingDomain ? 'Saving…' : 'Save & continue'}</button>
      <button class="ghost" onclick={() => saveDomain(true)} data-testid="wiz-skip-domain">Skip</button>
    </div>
    {#if domain && certAvailable}<p class="ok-line">✅ A trusted certificate is active for {domain}.</p>{/if}
  {:else if step === 2}
    <h3>2 · Create your first inbound</h3>
    <p class="hint">VLESS + REALITY is the most censorship-resistant option for Iran — it borrows a real website's TLS handshake. One click generates the keys, UUID and a steal-site.</p>
    {#if !inboundCreated}
      <button class="primary" onclick={createInbound} disabled={creatingInbound} data-testid="wiz-create-inbound">{creatingInbound ? 'Creating…' : '⚡ Create VLESS + REALITY'}</button>
    {:else}
      <p class="ok-line">✅ Created: <strong>{inboundInfo}</strong></p>
    {/if}
    <div class="nav">
      <button class="ghost" onclick={() => (step = 1)}>Back</button>
      <button class="primary" onclick={() => (step = 3)} disabled={!inboundCreated} data-testid="wiz-next-user">Next</button>
    </div>
  {:else if step === 3}
    <h3>3 · Create your first user</h3>
    <p class="hint">A user gets a private subscription link. Leave limits at 0 for unlimited / never-expires.</p>
    <div class="row">
      <input placeholder="username" bind:value={username} data-testid="wiz-username" />
      <input type="number" placeholder="limit GB (0=∞)" bind:value={limitGB} />
      <input type="number" placeholder="expire days (0=never)" bind:value={expireDays} />
    </div>
    <div class="nav">
      <button class="ghost" onclick={() => (step = 2)}>Back</button>
      <button class="primary" onclick={createUser} disabled={creatingUser} data-testid="wiz-create-user">{creatingUser ? 'Creating…' : 'Create user'}</button>
    </div>
  {:else}
    <h3>4 · Share the subscription 🎉</h3>
    <p class="hint">Send this link to the user, or open it in a browser for one-tap client import. Keep it private.</p>
    {#if subBase}
      <div class="share">
        <div class="qr"><QRCode value={subBase} size={180} /></div>
        <div class="links">
          <div class="linkrow"><code>{subBase}</code><button class="ghost sm" onclick={() => copy(subBase)} data-testid="wiz-copy-sub">Copy</button></div>
          <a class="ghost sm openbtn" href={subBase} target="_blank" rel="noreferrer">Open subscription page ↗</a>
          <p class="tiny">Clients: Hiddify · v2rayNG · NekoBox · sing-box · Clash Meta · Streisand. Routing (bypass-Iran, block ads/malware) and TLS Fragment are already applied — tune them in <strong>Users &amp; Subscriptions → Subscription defaults</strong>.</p>
        </div>
      </div>
      {#if !domain}<p class="warn-line">⚠️ You're on the IP with a self-signed cert. Some clients reject that — add a domain in step 1 for a trusted certificate.</p>{/if}
    {/if}
    <div class="nav"><button class="ghost" onclick={() => (step = 3)}>Back</button><button class="primary" onclick={() => (step = 1)}>Done — start over</button></div>
  {/if}
</div>

<style>
  .view-header h2 { margin: 0 0 20px; font-size: 20px; }
  .card { background: #141A24; border: 1px solid rgba(255,255,255,0.08); border-radius: 14px; padding: 22px; }
  .card h3 { margin: 0 0 10px; font-size: 16px; }
  .hint { color: rgba(255,255,255,0.6); font-size: 13px; margin: 0 0 16px; line-height: 1.5; }
  .stepper { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 18px; }
  .stepitem { display: flex; align-items: center; gap: 8px; padding: 8px 12px; border-radius: 10px; background: #0F1420; border: 1px solid rgba(255,255,255,0.08); font-size: 13px; color: rgba(255,255,255,0.55); }
  .stepitem.active { border-color: rgba(255,122,26,0.5); color: #FF9B4A; }
  .stepitem.done { color: #27D17C; }
  .stepitem .num { width: 22px; height: 22px; border-radius: 50%; background: rgba(255,255,255,0.08); display: inline-flex; align-items: center; justify-content: center; font-weight: 700; font-size: 12px; }
  .stepitem.active .num { background: #FF7A1A; color: #1a1204; }
  .stepitem.done .num { background: rgba(39,209,124,0.2); color: #27D17C; }
  .row { display: flex; gap: 10px; flex-wrap: wrap; }
  .row input { flex: 1; min-width: 160px; }
  input { background: #0F1420; border: 1px solid rgba(255,255,255,0.12); color: #fff; padding: 10px; border-radius: 8px; font: inherit; box-sizing: border-box; }
  .primary { background: #FF7A1A; color: #1a1204; border: none; font-weight: 700; padding: 10px 16px; border-radius: 8px; cursor: pointer; white-space: nowrap; }
  .primary:disabled { opacity: 0.5; cursor: default; }
  .ghost { background: #1A2230; color: #fff; border: 1px solid rgba(255,255,255,0.1); padding: 10px 16px; border-radius: 8px; cursor: pointer; font-weight: 600; }
  .ghost.sm { padding: 6px 12px; font-size: 12px; }
  .nav { display: flex; justify-content: space-between; margin-top: 18px; gap: 10px; }
  .preset { margin-bottom: 18px; border-color: rgba(255,122,26,0.35); }
  .pw-result { margin-top: 14px; }
  .pw-list { margin: 8px 0 0; padding-left: 18px; color: rgba(255,255,255,0.75); font-size: 13px; line-height: 1.7; }
  .pw-list li { word-break: break-word; }
  .ok-line { color: #27D17C; font-size: 14px; margin-top: 14px; }
  .warn-line { color: #FFC24B; font-size: 13px; margin-top: 14px; }
  .share { display: flex; gap: 20px; flex-wrap: wrap; align-items: flex-start; }
  .qr { background: #fff; padding: 10px; border-radius: 10px; }
  .links { flex: 1; min-width: 240px; display: flex; flex-direction: column; gap: 10px; }
  .linkrow { display: flex; gap: 8px; align-items: center; }
  .linkrow code { background: #0F1420; padding: 8px 10px; border-radius: 8px; font-size: 12px; word-break: break-all; flex: 1; }
  .openbtn { display: inline-block; width: fit-content; text-decoration: none; }
  .tiny { font-size: 12px; color: rgba(255,255,255,0.5); line-height: 1.5; margin: 4px 0 0; }
  code { background: #0F1420; padding: 2px 6px; border-radius: 6px; }
  @media (max-width: 768px) {
    .row { flex-direction: column; }
    .row input, .row .primary, .row .ghost { width: 100%; }
    .share { flex-direction: column; }
  }
</style>
