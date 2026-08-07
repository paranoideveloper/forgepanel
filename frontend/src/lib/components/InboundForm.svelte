<script lang="ts">
  import { onMount } from 'svelte';
  import { apiFetch } from '$lib/api';
  import { showToast } from '$lib/components/Toast.svelte';
  import { buildNode, fieldsFor, type Schema, type Field } from '$lib/nodebuild';

  let { onSaved = () => {}, initialProto = 'vless' } = $props<{
    onSaved?: () => void;
    initialProto?: string;
  }>();

  let schema = $state<Schema | null>(null);
  let proto = $state(initialProto);
  let transport = $state('tcp');
  let security = $state('reality');
  let values = $state<Record<string, any>>({ remark: '', port: 443, address: '' });
  let saving = $state(false);
  let loadError = $state('');

  // live preview
  let preview = $state<{ uri?: string; xray?: string; singbox?: string; clash?: string; errors?: any[] } | null>(null);
  let previewTab = $state<'uri' | 'xray' | 'singbox' | 'clash'>('uri');
  let previewing = $state(false);

  const current = $derived(schema?.protocols.find((p) => p.proto === proto) || null);
  const hasTransport = $derived(!!current?.transports?.length);
  const securities = $derived(current?.securities || []);
  const sections = $derived(schema ? fieldsFor(schema, proto, transport, security) : []);

  onMount(async () => {
    try {
      schema = await apiFetch<Schema>('/protocols/schema');
      // seed defaults for the initial protocol
      applyDefaults();
      schedulePreview();
    } catch (e: any) {
      loadError = e.message || 'failed to load protocol schema';
    }
  });

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
      const node = buildNode(schema, proto, transport, security, values);
      preview = await apiFetch('/studio/preview', { method: 'POST', body: JSON.stringify(node) });
    } catch (e: any) {
      preview = { errors: [{ severity: 'error', message: e.message || 'preview failed' }] };
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
      showToast(`Generated ${f.label}`, 'success');
      schedulePreview();
    } catch (e: any) {
      showToast(e.message || 'keygen failed', 'error');
    }
  }

  async function save() {
    if (!schema) return;
    saving = true;
    try {
      const node = buildNode(schema, proto, transport, security, values);
      const created = await apiFetch<{ id: number }>('/admin/inbounds', {
        method: 'POST',
        body: JSON.stringify(node),
      });
      showToast(`Inbound #${created.id} created (${proto})`, 'success');
      onSaved();
    } catch (e: any) {
      showToast(e.message || 'failed to create inbound', 'error');
    } finally {
      saving = false;
    }
  }

  function copyPreview() {
    const text = previewTab === 'uri' ? preview?.uri
      : previewTab === 'xray' ? preview?.xray
      : previewTab === 'singbox' ? preview?.singbox
      : preview?.clash;
    if (text) navigator.clipboard.writeText(text).then(() => showToast('Copied', 'success'));
  }
</script>

{#if loadError}
  <div class="err-box" data-testid="form-error">{loadError}</div>
{:else if !schema}
  <div class="muted">Loading protocol schema…</div>
{:else}
  <div class="builder">
    <div class="form-col">
      <div class="grid3">
        <div class="fg">
          <label for="proto">Protocol</label>
          <select id="proto" data-testid="proto-select" bind:value={proto} onchange={onProtoChange}>
            {#each schema.protocols as p}
              <option value={p.proto}>{p.label} ({p.engine})</option>
            {/each}
          </select>
        </div>
        {#if hasTransport}
          <div class="fg">
            <label for="transport">Transport</label>
            <select id="transport" bind:value={transport} onchange={schedulePreview}>
              {#each current?.transports || [] as t}<option value={t}>{t}</option>{/each}
            </select>
          </div>
        {/if}
        {#if securities.length}
          <div class="fg">
            <label for="security">Security</label>
            <select id="security" bind:value={security} onchange={schedulePreview}>
              {#each securities as sec}<option value={sec}>{sec}</option>{/each}
            </select>
          </div>
        {/if}
      </div>

      <div class="grid3">
        <div class="fg">
          <label for="remark">Remark</label>
          <input id="remark" data-testid="field-remark" bind:value={values['remark']} oninput={schedulePreview} placeholder="my-inbound" />
        </div>
        <div class="fg">
          <label for="port">Port</label>
          <input id="port" data-testid="field-port" type="number" bind:value={values['port']} oninput={schedulePreview} />
        </div>
        <div class="fg">
          <label for="address">Address (optional)</label>
          <input id="address" bind:value={values['address']} oninput={schedulePreview} placeholder="auto = panel host" />
        </div>
      </div>

      {#each sections as sec}
        <div class="section">
          <h4>{sec.section}</h4>
          <div class="fields">
            {#each sec.fields as f}
              <div class="fg" class:wide={f.type === 'textarea'}>
                <label for={f.key}>{f.label}</label>
                {#if f.type === 'bool'}
                  <label class="chk"><input type="checkbox" bind:checked={values[f.key]} onchange={schedulePreview} /> enabled</label>
                {:else if f.type === 'select' || f.type === 'iselect'}
                  <select id={f.key} bind:value={values[f.key]} onchange={schedulePreview}>
                    {#each f.options || [] as o}<option value={o}>{o === '' ? '(none)' : o}</option>{/each}
                  </select>
                {:else if f.type === 'textarea'}
                  <textarea id={f.key} bind:value={values[f.key]} oninput={schedulePreview} placeholder={f.placeholder}></textarea>
                {:else}
                  <div class="with-gen">
                    <input id={f.key} type={f.type === 'number' ? 'number' : 'text'}
                      bind:value={values[f.key]} oninput={schedulePreview} placeholder={f.placeholder} />
                    {#if f.keygen}
                      <button type="button" class="gen" data-testid={'gen-' + f.key} onclick={() => generate(f)}>Generate</button>
                    {/if}
                  </div>
                {/if}
                {#if f.help}<span class="help">{f.help}</span>{/if}
              </div>
            {/each}
          </div>
        </div>
      {/each}

      <button class="save" data-testid="save-inbound" onclick={save} disabled={saving}>
        {saving ? 'Saving…' : 'Save Inbound'}
      </button>
    </div>

    <div class="preview-col">
      <div class="preview-head">
        <div class="tabs">
          {#each (['uri', 'xray', 'singbox', 'clash'] as const) as t}
            <button class:active={previewTab === t} onclick={() => previewTab = t}>{t === 'uri' ? 'Client Link' : t}</button>
          {/each}
        </div>
        <button class="copy" onclick={copyPreview}>Copy</button>
      </div>
      {#if preview?.errors?.length}
        <div class="errors" data-testid="preview-errors">
          {#each preview.errors as e}<div class="e {e.severity}">{e.severity}: {e.message}</div>{/each}
        </div>
      {/if}
      <pre data-testid="preview-body">{#if previewTab === 'uri'}{preview?.uri || (previewing ? 'rendering…' : '—')}{:else if previewTab === 'xray'}{preview?.xray || '—'}{:else if previewTab === 'singbox'}{preview?.singbox || '—'}{:else}{preview?.clash || '—'}{/if}</pre>
    </div>
  </div>
{/if}

<style>
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
  .help { font-size: 11px; color: rgba(255,255,255,0.4); }
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
