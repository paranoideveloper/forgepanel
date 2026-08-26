<script lang="ts">
	import { tr } from '$lib/i18n';
  import { onMount } from 'svelte';
  import { apiFetch } from '$lib/api';
  import { showToast } from '$lib/components/Toast.svelte';
  import { buildNode, fieldsFor, getPath, formatKV, type Schema, type Field } from '$lib/nodebuild';

  let { onSaved = () => {}, initialProto = 'vless', initial = null, editId = 0 } = $props<{
    onSaved?: () => void;
    initialProto?: string;
    initial?: Record<string, any> | null;
    editId?: number;
  }>();

  let schema = $state<Schema | null>(null);
  let proto = $state(initialProto);
  let transport = $state('tcp');
  let security = $state('reality');
  let values = $state<Record<string, any>>({ remark: '', port: 443, address: '', country: '' });
  let saving = $state(false);
  let loadError = $state('');

  // live preview
  let preview = $state<{ uri?: string; xray?: string; singbox?: string; clash?: string; errors?: any[] } | null>(null);
  let previewTab = $state<'uri' | 'xray' | 'singbox' | 'clash'>('uri');
  let previewing = $state(false);

  // Port hopping installs nftables/iptables redirects, which needs
  // CAP_NET_ADMIN from the HOST. The capability check existed and nothing ever
  // called it, so an operator typed a hop range, the panel accepted it, and the
  // rules were never installed — the inbound served only its base port and the
  // range did nothing at all.
  let hopCap = $state<{ supported: boolean; reason?: string; remediation?: string } | null>(null);
  const hopRange = $derived(String(values['hysteria2.port_hopping'] ?? '').trim());
  const hopWontWork = $derived(
    proto === 'hysteria2' && hopRange !== '' && hopCap !== null && !hopCap.supported
  );

  const current = $derived(schema?.protocols.find((p) => p.proto === proto) || null);
  const hasTransport = $derived(!!current?.transports?.length);
  const securities = $derived(current?.securities || []);
  const sections = $derived(schema ? fieldsFor(schema, proto, transport, security) : []);

  onMount(async () => {
    try {
      schema = await apiFetch<Schema>('/protocols/schema');
      // Seed BEFORE the next await.
      //
      // Awaiting /capabilities yields, and Svelte flushes the DOM in that gap.
      // The selects mount while their bound values are still undefined, and a
      // select binding with no matching option writes the FIRST option back
      // into the bound value. applyDefaults then sees a value that is no longer
      // undefined and skips the default entirely — so every iselect silently
      // took its first option instead of its documented default, and nothing
      // looked wrong because a value was always selected.
      if (initial) prefillFrom(initial);
      else applyDefaults();
      try {
        const caps = await apiFetch<{ port_hopping?: typeof hopCap }>('/capabilities');
        hopCap = caps.port_hopping ?? null;
      } catch {
        // A missing capability report must not block the form. Unknown is shown
        // as nothing rather than as a false reassurance.
        hopCap = null;
      }
      schedulePreview();
    } catch (e: any) {
      loadError = e.message || tr('inbound.failed_to_load_protocol_schema');
    }
  });

  // prefillFrom decomposes an existing node back into the flat form model, so an
  // inbound can be edited with every field pre-populated.
  let originalNode: Record<string, any> | null = null;

  function prefillFrom(node: Record<string, any>) {
    if (!schema) return;
    // Keep the node exactly as the server returned it. buildNode starts from
    // this on save so fields the studio schema does not describe (Egress, xmux,
    // download_settings, ECH, peer keys) survive an edit instead of being
    // replaced with nothing.
    originalNode = structuredClone(node);
    proto = node.protocol || proto;
    transport = node.transport?.network || 'tcp';
    security = node.security?.type || 'none';
    values['remark'] = node.remark ?? '';
    values['port'] = node.port ?? 443;
    values['address'] = node.address ?? '';
    values['country'] = node.country ?? '';
    for (const sec of fieldsFor(schema, proto, transport, security)) {
      for (const f of sec.fields) {
        const v = getPath(node, f.key);
        if (v === undefined) continue;
        // A kv map must go back to "Name: value" lines; assigning the object
        // straight into a textarea renders "[object Object]" and then saves
        // that string as the header set.
        // A `lines` field joins with newlines, not commas: its values are share
        // links that legitimately contain commas.
        values[f.key] =
          f.type === 'kv'
            ? formatKV(v)
            : f.type === 'lines'
              ? (Array.isArray(v) ? v.join('\n') : String(v))
              : Array.isArray(v)
                ? v.join(',')
                : v;
      }
    }
  }

  function applyDefaults() {
    if (!schema) return;
    const ps = schema.protocols.find((p) => p.proto === proto);
    if (!ps) return;
    // pick sensible transport/security for the protocol
    transport = ps.transports?.length ? (ps.transports.includes('tcp') ? 'tcp' : ps.transports[0]) : '';
    if (ps.securities?.length) {
      security = ps.securities.includes('reality') ? 'reality'
        : ps.securities.includes('tls') ? 'tls' : ps.securities[0];
    } else {
      security = '';
    }
    // seed field defaults
    const collect: Field[] = [
      ...ps.fields,
      ...(transport ? schema.transports[transport] || [] : []),
      ...(security ? schema.securities[security] || [] : []),
    ];
    for (const f of collect) {
      if (values[f.key] === undefined && f.default !== undefined) values[f.key] = f.default;
    }
  }

  function onProtoChange() {
    applyDefaults();
    schedulePreview();
  }

  let previewTimer: ReturnType<typeof setTimeout> | null = null;
  function schedulePreview() {
    if (previewTimer) clearTimeout(previewTimer);
    previewTimer = setTimeout(runPreview, 250);
  }

  async function runPreview() {
    if (!schema) return;
    previewing = true;
    try {
      const node = buildNode(schema, proto, transport, security, values, editId ? originalNode : null);
      preview = await apiFetch('/studio/preview', { method: 'POST', body: JSON.stringify(node) });
    } catch (e: any) {
      preview = { errors: [{ severity: 'error', message: e.message || tr('inbound.preview_failed') }] };
    } finally {
      previewing = false;
    }
  }

  async function generate(f: Field) {
    if (!f.keygen) return;
    try {
      let kind = f.keygen;
      const method = String(values['method'] || '');
      // Shadowsocks 2022 needs an exact-length base64 PSK, not a generic
      // password — the static schema can't know the method, so switch here.
      if (proto === 'shadowsocks' && f.key === 'password' && method.startsWith('2022-')) {
        kind = 'ss2022';
      }
      const resp = await apiFetch<Record<string, any>>('/keygen', {
        method: 'POST',
        body: JSON.stringify({ kind, method }),
      });
      const val = resp.private_key ?? resp.uuid ?? resp.short_id ?? resp.psk ?? resp.password ?? resp.seed;
      if (val !== undefined) values[f.key] = val;
      // reality/wireguard also return a public key — fill the sibling field.
      if (resp.public_key !== undefined) {
        const sib = f.key.replace(/private_key$/, 'public_key');
        if (sib !== f.key) values[sib] = resp.public_key;
      }
      showToast(tr('inbound.generated_label', { label: f.label }), 'success');
      schedulePreview();
    } catch (e: any) {
      showToast(e.message || tr('inbound.keygen_failed'), 'error');
    }
  }

  let detecting = $state(false);
  // Auto-fill the country from the address (or the panel's own IP when blank),
  // so {FLAG}/{COUNTRY} in the naming template need no manual code. On failure
  // (a locked-down network) the operator just types the 2-letter code.
  async function detectCountry() {
    detecting = true;
    try {
      const host = String(values['address'] || '').trim();
      const q = host ? `?host=${encodeURIComponent(host)}` : '';
      const r = await apiFetch<{ country_code: string; flag: string }>(`/admin/geoip${q}`);
      values['country'] = r.country_code;
      schedulePreview();
      showToast(tr('inbound.detected_flag_country_code', { flag: r.flag, country_code: r.country_code }), 'success');
    } catch (e: any) {
      showToast(e.message || tr('inbound.could_not_detect_country_enter_it'), 'error');
    } finally {
      detecting = false;
    }
  }

  let breakingOpen = $state(false);
  let breakingChanges = $state<string[]>([]);

  // applyBreaking re-sends the edit once the operator has seen what it breaks.
  // keep_old leaves the current inbound alive but disabled, as a migration copy,
  // so clients already using it are not cut off the moment the change lands.
  async function applyBreaking(keepOld: boolean) {
    if (!schema || !editId) return;
    saving = true;
    try {
      const node = buildNode(schema, proto, transport, security, values, originalNode);
      const q = keepOld ? '?confirm=true&keep_old=true' : '?confirm=true';
      await apiFetch(`/admin/inbounds/${editId}${q}`, { method: 'PUT', body: JSON.stringify(node) });
      showToast(tr('inbound.inbound_editid_updated', { editId }), 'success');
      breakingOpen = false;
      onSaved();
    } catch (e: any) {
      showToast(e.message || tr('inbound.failed_to_create_inbound'), 'error');
    } finally {
      saving = false;
    }
  }

  async function save() {
    if (!schema) return;
    saving = true;
    try {
      const node = buildNode(schema, proto, transport, security, values, editId ? originalNode : null);
      if (editId) {
        // NOT confirm=true unconditionally.
        //
        // The safe-edit guard exists to tell an operator that a change
        // invalidates every client config already handed out — a changed port,
        // protocol, transport or security. Hardcoding confirm=true answered
        // that question for them, every time, without asking: the guard ran,
        // found breaking changes, and was overruled before anyone saw it.
        await apiFetch(`/admin/inbounds/${editId}`, { method: 'PUT', body: JSON.stringify(node) });
        showToast(tr('inbound.inbound_editid_updated', { editId }), 'success');
      } else {
        const created = await apiFetch<{ id: number }>('/admin/inbounds', { method: 'POST', body: JSON.stringify(node) });
        showToast(tr('inbound.inbound_id_created_proto', { id: created.id, proto }), 'success');
      }
      onSaved();
    } catch (e: any) {
      if (e?.code === 'breaking_edit') {
        breakingChanges = (e.body?.breaking as string[]) ?? [];
        breakingOpen = true;
        return;
      }
      showToast(e.message || tr('inbound.failed_to_create_inbound'), 'error');
    } finally {
      saving = false;
    }
  }

  function copyPreview() {
    const text = previewTab === 'uri' ? preview?.uri
      : previewTab === 'xray' ? preview?.xray
      : previewTab === 'singbox' ? preview?.singbox
      : preview?.clash;
    if (text) navigator.clipboard.writeText(text).then(() => showToast(tr('inbound.copied'), 'success'));
  }
</script>

{#if loadError}
  <div class="err-box" data-testid="form-error">{loadError}</div>
{:else if !schema}
  <div class="muted">{tr('inbound.loading_protocol_schema')}</div>
{:else}
  <div class="builder">
    <div class="form-col">
      <div class="grid3">
        <div class="fg">
          <label for="proto">{tr('inbound.protocol')}</label>
          <select id="proto" data-testid="proto-select" bind:value={proto} onchange={onProtoChange}>
            <!-- Only protocols the panel can actually LISTEN on. SSH is
                 dialable as an egress hop and has no server side here, and
                 offering it produced an inbound that failed to render on every
                 reload while looking configured. -->
            {#each schema.protocols.filter((p) => p.serves_inbound !== false) as p}
              <option value={p.proto}>{p.label} ({p.engine})</option>
            {/each}
          </select>
        </div>
        {#if hasTransport}
          <div class="fg">
            <label for="transport">{tr('inbound.transport')}</label>
            <select id="transport" bind:value={transport} onchange={schedulePreview}>
              {#each current?.transports || [] as t}<option value={t}>{t}</option>{/each}
            </select>
          </div>
        {/if}
        {#if securities.length}
          <div class="fg">
            <label for="security">{tr('inbound.security')}</label>
            <select id="security" bind:value={security} onchange={schedulePreview}>
              {#each securities as sec}<option value={sec}>{sec}</option>{/each}
            </select>
          </div>
        {/if}
      </div>

      <div class="grid3">
        <div class="fg">
          <label for="remark">{tr('inbound.remark')}</label>
          <input id="remark" data-testid="field-remark" bind:value={values['remark']} oninput={schedulePreview} placeholder={tr('inbound.my_inbound')} />
        </div>
        <div class="fg">
          <label for="port">{tr('inbound.port')}</label>
          <input id="port" data-testid="field-port" type="number" bind:value={values['port']} oninput={schedulePreview} />
        </div>
        <div class="fg">
          <label for="address">{tr('inbound.address_optional')}</label>
          <input id="address" bind:value={values['address']} oninput={schedulePreview} placeholder={tr('inbound.auto_panel_host')} />
        </div>
        <div class="fg">
          <label for="country">{tr('inbound.country')}</label>
          <div style="display:flex;gap:6px">
            <input id="country" data-testid="field-country" bind:value={values['country']} oninput={schedulePreview} maxlength="2" placeholder={tr('inbound.e_g_de')} title={tr('inbound.iso_2_letter_code_the_flag')} style="text-transform:uppercase;flex:1" />
            <button type="button" class="detect" onclick={detectCountry} disabled={detecting} title={tr('inbound.auto_detect_from_the_address_geoip')}>{detecting ? '…' : 'Detect'}</button>
          </div>
        </div>
      </div>

      {#each sections as sec}
        <div class="section">
          <h4>{sec.section}</h4>
          <div class="fields">
            {#each sec.fields as f}
              <div class="fg" class:wide={f.type === 'textarea' || f.type === 'kv' || f.type === 'lines'}>
                <label for={f.key}>{f.label}</label>
                {#if f.type === 'bool'}
                  <label class="chk"><input type="checkbox" bind:checked={values[f.key]} onchange={schedulePreview} /> {tr('inbound.enabled')}</label>
                {:else if f.type === 'select' || f.type === 'iselect'}
                  <select id={f.key} bind:value={values[f.key]} onchange={schedulePreview}>
                    {#each f.options || [] as o}<option value={o}>{o === '' ? '(none)' : o}</option>{/each}
                  </select>
                {:else if f.type === 'textarea' || f.type === 'kv' || f.type === 'lines'}
                  <textarea id={f.key} bind:value={values[f.key]} oninput={schedulePreview} placeholder={f.placeholder}></textarea>
                {:else}
                  <div class="with-gen">
                    <input id={f.key} type={f.type === 'number' ? 'number' : 'text'}
                      bind:value={values[f.key]} oninput={schedulePreview} placeholder={f.placeholder} />
                    {#if f.keygen}
                      <button type="button" class="gen" data-testid={'gen-' + f.key} onclick={() => generate(f)}>{tr('inbound.generate')}</button>
                    {/if}
                  </div>
                {/if}
                {#if f.help}<span class="help">{f.help}</span>{/if}
              </div>
            {/each}
          </div>
        </div>
      {/each}

      <!-- Shown, not blocking. The inbound is still perfectly usable on its
           base port, and refusing to save would take a working configuration
           away over a host permission the operator may be about to grant. -->
      {#if hopWontWork}
        <div class="hop-warning" data-testid="hop-warning">
          <strong>{tr('inbound.port_hopping_will_not_take_effect')}</strong>
          <span>{hopCap?.reason}</span>
          {#if hopCap?.remediation}<span>{hopCap.remediation}</span>{/if}
        </div>
      {/if}

      <button class="save" data-testid="save-inbound" onclick={save} disabled={saving}>
        {saving ? tr('inbound.saving') : editId ? tr('inbound.update_inbound') : tr('inbound.save_inbound')}
      </button>
    </div>

    <div class="preview-col">
      <div class="preview-head">
        <div class="tabs">
          {#each (['uri', 'xray', 'singbox', 'clash'] as const) as t}
            <button class:active={previewTab === t} onclick={() => previewTab = t}>{t === 'uri' ? tr('inbound.client_link') : t}</button>
          {/each}
        </div>
        <button class="copy" onclick={copyPreview}>{tr('inbound.copy')}</button>
      </div>
      {#if preview?.errors?.length}
        <div class="errors" data-testid="preview-errors">
          {#each preview.errors as e}<div class="e {e.severity}">{e.severity}: {e.message}</div>{/each}
        </div>
      {/if}
      <pre data-testid="preview-body">{#if previewTab === 'uri'}{preview?.uri || (previewing ? tr('inbound.rendering') : '—')}{:else if previewTab === 'xray'}{preview?.xray || '—'}{:else if previewTab === 'singbox'}{preview?.singbox || '—'}{:else}{preview?.clash || '—'}{/if}</pre>
    </div>
  </div>
{/if}

<!-- The safe-edit guard's answer, shown to the operator instead of being
     overruled on their behalf. -->
{#if breakingOpen}
  <div class="breaking" data-testid="breaking-edit">
    <h4>{tr('inbound.breaking_title')}</h4>
    <p class="hint">{tr('inbound.breaking_explainer')}</p>
    <ul>
      {#each breakingChanges as b}<li>{b}</li>{/each}
    </ul>
    <div class="brow">
      <button class="sm" data-testid="breaking-keep-old" onclick={() => applyBreaking(true)} disabled={saving}>
        {tr('inbound.breaking_keep_old')}
      </button>
      <button class="sm danger" data-testid="breaking-apply" onclick={() => applyBreaking(false)} disabled={saving}>
        {tr('inbound.breaking_apply')}
      </button>
      <button class="sm" onclick={() => (breakingOpen = false)}>{tr('inbound.breaking_cancel')}</button>
    </div>
  </div>
{/if}

<style>
  .hop-warning {
    display: flex;
    flex-direction: column;
    gap: 6px;
    margin-bottom: 12px;
    padding: 12px 14px;
    border: 1px solid rgba(217, 155, 43, 0.4);
    background: rgba(217, 155, 43, 0.1);
    border-radius: 10px;
    font-size: 12px;
    line-height: 1.6;
    color: #d99b2b;
  }
  .hop-warning strong { font-size: 13px; }

  .builder { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; align-items: start; }
  @media (max-width: 900px) { .builder { grid-template-columns: 1fr; } }
  .grid3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 8px; }
  .section { margin-top: 14px; border-top: 1px solid rgba(255,255,255,0.08); padding-top: 12px; }
  .section h4 { margin: 0 0 10px; font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; color: #FF9A4A; }
  .fields { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .fg { display: flex; flex-direction: column; gap: 5px; min-width: 0; }
  .fg.wide, .fields .fg.wide { grid-column: 1 / -1; }
  label { font-size: 12px; color: rgba(255,255,255,0.7); }
  input, select, textarea {
    width: 100%; box-sizing: border-box; background: #0F1420;
    border: 1px solid rgba(255,255,255,0.12); color: #fff; padding: 9px 10px;
    border-radius: 8px; font: inherit; font-size: 13px;
  }
  input:focus, select:focus, textarea:focus { outline: none; border-color: #FF7A1A; }
  textarea { min-height: 60px; font-family: monospace; }
  .chk { flex-direction: row; display: flex; align-items: center; gap: 8px; font-size: 13px; color: #fff; }
  .chk input { width: auto; }
  .with-gen { display: flex; gap: 8px; }
  .with-gen input { flex: 1; }
  .gen { background: #1A2230; color: #FF9A4A; border: 1px solid rgba(255,122,26,0.4); border-radius: 8px; padding: 0 12px; cursor: pointer; font-size: 12px; white-space: nowrap; }
  .breaking { margin-top: 14px; padding: 12px; border: 1px solid rgba(248,113,113,0.4); border-radius: 10px; background: rgba(248,113,113,0.06); }
  .breaking h4 { margin: 0 0 6px; font-size: 14px; }
  .breaking ul { margin: 8px 0; padding-inline-start: 20px; font-size: 13px; }
  .brow { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 10px; }
  .help { font-size: 11px; color: rgba(255,255,255,0.4); }
  .detect { background: rgba(255,255,255,0.06); color: #fff; border: 1px solid rgba(255,255,255,0.14); border-radius: 8px; padding: 0 12px; font-size: 12px; font-weight: 600; cursor: pointer; white-space: nowrap; }
  .detect:hover { background: rgba(255,255,255,0.12); }
  .detect:disabled { opacity: 0.6; cursor: default; }
  .save { margin-top: 18px; width: 100%; background: #FF7A1A; color: #1a1204; border: none; font-weight: 700; padding: 12px; border-radius: 10px; cursor: pointer; font-size: 14px; }
  .save:disabled { opacity: 0.6; cursor: default; }
  .preview-col { background: #0B0F16; border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; padding: 14px; position: sticky; top: 12px; }
  .preview-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
  .tabs { display: flex; gap: 4px; flex-wrap: wrap; }
  .tabs button { background: #141A24; border: 1px solid rgba(255,255,255,0.1); color: rgba(255,255,255,0.7); padding: 5px 10px; border-radius: 6px; font-size: 12px; cursor: pointer; }
  .tabs button.active { background: rgba(255,122,26,0.15); color: #FF7A1A; border-color: #FF7A1A; }
  .copy { background: #1A2230; color: #fff; border: 1px solid rgba(255,255,255,0.1); padding: 5px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; }
  pre { background: #0F1420; padding: 12px; border-radius: 8px; overflow-x: auto; color: #27D17C; font-family: monospace; font-size: 12px; margin: 0; white-space: pre-wrap; word-break: break-all; max-height: 480px; }
  .errors { margin-bottom: 8px; }
  .e { font-size: 12px; padding: 4px 8px; border-radius: 6px; margin-bottom: 4px; }
  .e.error { background: rgba(255,77,77,0.15); color: #FF4D4D; }
  .e.warn { background: rgba(255,180,0,0.12); color: #FFB400; }
  .err-box { background: rgba(255,77,77,0.15); color: #FF4D4D; padding: 12px; border-radius: 8px; }
  .muted { color: rgba(255,255,255,0.5); padding: 20px; }
</style>
