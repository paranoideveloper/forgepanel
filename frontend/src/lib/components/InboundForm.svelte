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

  // Which protocol/transport/security triples the engine will actually accept.
  //
  // /capabilities has always carried this, and the builder read one field of it
  // (port_hopping) and ignored the rest — so the security dropdown offered
  // REALITY over WebSocket, the operator filled in the whole form, pressed Save,
  // and the validator returned a 400 it could have given before the first field
  // was typed. The matrix comes from running model.Validate on each triple, so a
  // greyed-out option carries the validator's own words.
  interface Combination { protocol: string; transport: string; security: string; supported: boolean; reason?: string }
  let combinations = $state<Combination[]>([]);

  function comboFor(p: string, t: string, sec: string): Combination | undefined {
    return combinations.find((c) => c.protocol === p && c.transport === (t || '') && c.security === (sec || ''));
  }
  // Unknown means allowed: an older panel, or a capability call that failed,
  // must not silently forbid combinations that work.
  const securityBlocked = (sec: string) => comboFor(proto, transport, sec)?.supported === false;
  const securityReason = (sec: string) => comboFor(proto, transport, sec)?.reason ?? '';
  let securityMoved = $state('');
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
      lastProto = proto;
      try {
        const caps = await apiFetch<{ port_hopping?: typeof hopCap; combinations?: Combination[] }>('/capabilities');
        hopCap = caps.port_hopping ?? null;
        combinations = caps.combinations ?? [];
      } catch {
        // A missing capability report must not block the form. Unknown is shown
        // as nothing rather than as a false reassurance — and with no matrix
        // every option stays selectable, which is how the form behaved before
        // the matrix existed.
        hopCap = null;
        combinations = [];
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
    //
    // Snapshot first. structuredClone THROWS on a Svelte $state proxy —
    // "#<Object> could not be cloned" — and the throw lands in onMount, so the
    // whole form renders as a load error with no field on it. The edit path
    // never hit it because that node comes straight out of apiFetch as plain
    // JSON; a caller holding the node in reactive state does, which is exactly
    // what the Config Studio does with the preset it picked.
    originalNode = structuredClone($state.snapshot(node));
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

  // Switching protocol used to call applyDefaults() and nothing else: every
  // field the operator had filled in was silently replaced, and on an edit that
  // includes the credential every existing client is using. The server has an
  // endpoint that says exactly what a switch keeps, what it clears and what it
  // mints fresh — POST /protocols/switch/preview, built and never called from
  // anywhere in the panel.
  //
  // The switch is applied straight away, because nothing is saved until Save is
  // pressed and a modal in front of a dropdown is friction for no safety. What
  // was missing is the STATEMENT of what happened, so the summary appears above
  // the form and the switch can be undone from it.
  interface FieldChange { field: string; value?: string; why?: string }
  interface SwitchSummary {
    from_protocol: string; to_protocol: string;
    from_engine: string; to_engine: string; engine_changed: boolean;
    retained: FieldChange[]; reset: FieldChange[]; regenerated: FieldChange[];
    required_ports?: { port: number; why?: string }[];
    warnings?: string[];
  }
  type FormState = { proto: string; transport: string; security: string; values: Record<string, any> };

  let switchSummary = $state<SwitchSummary | null>(null);
  let switchInvalid = $state('');
  let undoSwitch$ = $state<FormState | null>(null);
  // The protocol the current `values` belong to. `bind:value` has already moved
  // `proto` to the new one by the time onchange fires, so without this the node
  // sent for preview would claim to be the target already and the server would
  // be asked to describe a switch from a protocol to itself.
  let lastProto = initialProto;

  async function onProtoChange() {
    const target = proto;
    if (!schema || target === lastProto) return;
    const previous: FormState = { proto: lastProto, transport, security, values: { ...values } };

    let node: Record<string, any>;
    try {
      node = buildNode(schema, previous.proto, previous.transport, previous.security, previous.values,
                       editId ? originalNode : null);
    } catch {
      applyDefaults();
      lastProto = target;
      schedulePreview();
      return;
    }

    try {
      const res = await apiFetch<{ summary: SwitchSummary; node: Record<string, any>; valid: boolean; error?: string }>(
        '/protocols/switch/preview',
        { method: 'POST', body: JSON.stringify({ node, target_protocol: target }) }
      );
      prefillFrom(res.node);
      proto = target;
      undoSwitch$ = previous;
      switchSummary = res.summary;
      switchInvalid = res.valid ? '' : (res.error ?? '');
    } catch {
      // The preview is an explanation, not a gate. If it cannot be reached the
      // switch still happens the way it always did — refusing to change protocol
      // because the description of the change is unavailable would be worse.
      applyDefaults();
      undoSwitch$ = null;
      switchSummary = null;
      switchInvalid = '';
    }
    lastProto = proto;
    schedulePreview();
  }

  // Changing the transport can invalidate the security that is already
  // selected. Leaving it selected would leave a form whose own dropdown shows a
  // disabled value, and saving it would fail; moving it silently would change a
  // setting the operator chose without telling them. So it moves and says so.
  function onTransportChange() {
    if (securityBlocked(security)) {
      const why = securityReason(security);
      const fallback = (securities as string[]).find((sec) => !securityBlocked(sec));
      if (fallback !== undefined) {
        securityMoved = tr('inbound.security_moved', { from: security, to: fallback, why });
        security = fallback;
      }
    } else {
      securityMoved = '';
    }
    schedulePreview();
  }

  function onSecurityChange() {
    securityMoved = '';
    schedulePreview();
  }

  function undoProtoSwitch() {
    const prev = undoSwitch$;
    if (!prev) return;
    proto = prev.proto;
    transport = prev.transport;
    security = prev.security;
    values = { ...prev.values };
    lastProto = prev.proto;
    undoSwitch$ = null;
    switchSummary = null;
    switchInvalid = '';
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
                 reload while looking configured.

                 serves_here narrows it further to what THIS deployment can
                 serve. Behind a platform edge that is three protocols out of
                 fifteen, and offering the rest walks the operator into an
                 inbound that is accepted, looks configured, and carries
                 nothing. -->
            {#each schema.protocols.filter((p) => p.serves_inbound !== false && p.serves_here !== false) as p}
              <option value={p.proto}>{p.label} ({p.engine})</option>
            {/each}
          </select>
        </div>
        {#if hasTransport}
          <div class="fg">
            <label for="transport">{tr('inbound.transport')}</label>
            <select id="transport" data-testid="transport-select" bind:value={transport} onchange={onTransportChange}>
              {#each current?.transports || [] as t}<option value={t}>{t}</option>{/each}
            </select>
          </div>
        {/if}
        {#if securities.length}
          <div class="fg">
            <label for="security">{tr('inbound.security')}</label>
            <select id="security" data-testid="security-select" bind:value={security} onchange={onSecurityChange}>
              {#each securities as sec}
                <option value={sec} disabled={securityBlocked(sec)} title={securityReason(sec)}>{sec}</option>
              {/each}
            </select>
            {#if securityMoved}
              <span class="moved" data-testid="security-moved">{securityMoved}</span>
            {/if}
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

      <!-- What the protocol switch just did. Shown after the fact, because
           nothing is written until Save; the point is that the operator is told
           which fields were cleared and which credentials were re-minted, rather
           than watching the form empty itself with no explanation. -->
      {#if switchSummary}
        <div class="switch-summary" data-testid="switch-summary">
          <div class="sw-head">
            <strong>{tr('inbound.switched_protocol', { from: switchSummary.from_protocol, to: switchSummary.to_protocol })}</strong>
            <button type="button" class="sm" data-testid="switch-undo" onclick={undoProtoSwitch}>{tr('inbound.undo_switch')}</button>
            <button type="button" class="sm" data-testid="switch-dismiss" onclick={() => (switchSummary = null)}>{tr('inbound.dismiss')}</button>
          </div>
          {#if switchSummary.engine_changed}
            <span class="sw-line" data-testid="switch-engine">{tr('inbound.switch_engine_changed', { from: switchSummary.from_engine, to: switchSummary.to_engine })}</span>
          {/if}
          {#if switchInvalid}
            <span class="sw-line err" data-testid="switch-invalid">{tr('inbound.switch_invalid', { why: switchInvalid })}</span>
          {/if}
          {#if switchSummary.reset?.length}
            <span class="sw-line" data-testid="switch-reset">{tr('inbound.switch_cleared')} {switchSummary.reset.map((c) => c.field).join(', ')}</span>
          {/if}
          {#if switchSummary.regenerated?.length}
            <span class="sw-line" data-testid="switch-regenerated">{tr('inbound.switch_regenerated')} {switchSummary.regenerated.map((c) => c.field).join(', ')}</span>
          {/if}
          {#if switchSummary.retained?.length}
            <span class="sw-line muted-line" data-testid="switch-retained">{tr('inbound.switch_kept')} {switchSummary.retained.map((c) => c.field).join(', ')}</span>
          {/if}
          {#each switchSummary.required_ports ?? [] as rp}
            <span class="sw-line" data-testid="switch-port">{tr('inbound.switch_needs_port', { port: rp.port, why: rp.why ?? '' })}</span>
          {/each}
          {#each switchSummary.warnings ?? [] as w}
            <span class="sw-line err" data-testid="switch-warning">{w}</span>
          {/each}
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
  .switch-summary {
    display: flex;
    flex-direction: column;
    gap: 5px;
    margin: 10px 0 14px;
    padding: 10px 12px;
    border: 1px solid rgba(255,122,26,0.35);
    background: rgba(255,122,26,0.08);
    border-radius: 8px;
    font-size: 12px;
  }
  .sw-head { display: flex; align-items: center; gap: 8px; }
  .sw-head strong { flex: 1; }
  .sw-line { color: var(--t-2); }
  .sw-line.muted-line { color: var(--t-8); }
  .sw-line.err { color: var(--bad-3); }
  .moved { font-size: 11px; color: var(--acc-2); margin-top: 4px; display: block; }
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
    color: var(--warn);
  }
  .hop-warning strong { font-size: 13px; }

  .builder { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; align-items: start; }
  @media (max-width: 900px) { .builder { grid-template-columns: 1fr; } }
  .grid3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 8px; }
  .section { margin-top: 14px; border-top: 1px solid var(--ln-3); padding-top: 12px; }
  .section h4 { margin: 0 0 10px; font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--acc-2); }
  .fields { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .fg { display: flex; flex-direction: column; gap: 5px; min-width: 0; }
  .fg.wide, .fields .fg.wide { grid-column: 1 / -1; }
  label { font-size: 12px; color: var(--t-3); }
  input, select, textarea {
    width: 100%; box-sizing: border-box; background: var(--bg);
    border: 1px solid var(--ln-5); color: var(--fg); padding: 9px 10px;
    border-radius: 8px; font: inherit; font-size: 13px;
  }
  input:focus, select:focus, textarea:focus { outline: none; border-color: var(--acc); }
  textarea { min-height: 60px; font-family: monospace; }
  .chk { flex-direction: row; display: flex; align-items: center; gap: 8px; font-size: 13px; color: var(--fg); }
  .chk input { width: auto; }
  .with-gen { display: flex; gap: 8px; }
  .with-gen input { flex: 1; }
  .gen { background: var(--raised); color: var(--acc-2); border: 1px solid rgba(255,122,26,0.4); border-radius: 8px; padding: 0 12px; cursor: pointer; font-size: 12px; white-space: nowrap; }
  .breaking { margin-top: 14px; padding: 12px; border: 1px solid rgba(248,113,113,0.4); border-radius: 10px; background: rgba(248,113,113,0.06); }
  .breaking h4 { margin: 0 0 6px; font-size: 14px; }
  .breaking ul { margin: 8px 0; padding-inline-start: 20px; font-size: 13px; }
  .brow { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 10px; }
  .help { font-size: 11px; color: var(--t-8); }
  .detect { background: var(--ln-2); color: var(--fg); border: 1px solid var(--ln-5); border-radius: 8px; padding: 0 12px; font-size: 12px; font-weight: 600; cursor: pointer; white-space: nowrap; }
  .detect:hover { background: var(--ln-5); }
  .detect:disabled { opacity: 0.6; cursor: default; }
  .save { margin-top: 18px; width: 100%; background: var(--acc); color: var(--acc-soft); border: none; font-weight: 700; padding: 12px; border-radius: 10px; cursor: pointer; font-size: 14px; }
  .save:disabled { opacity: 0.6; cursor: default; }
  .preview-col { background: var(--bg-deep); border: 1px solid var(--ln-3); border-radius: 12px; padding: 14px; position: sticky; top: 12px; }
  .preview-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
  .tabs { display: flex; gap: 4px; flex-wrap: wrap; }
  .tabs button { background: var(--card); border: 1px solid var(--ln-4); color: var(--t-3); padding: 5px 10px; border-radius: 6px; font-size: 12px; cursor: pointer; }
  .tabs button.active { background: rgba(255,122,26,0.15); color: var(--acc); border-color: var(--acc); }
  .copy { background: var(--raised); color: var(--fg); border: 1px solid var(--ln-4); padding: 5px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; }
  pre { background: var(--bg); padding: 12px; border-radius: 8px; overflow-x: auto; color: var(--ok); font-family: monospace; font-size: 12px; margin: 0; white-space: pre-wrap; word-break: break-all; max-height: 480px; }
  .errors { margin-bottom: 8px; }
  .e { font-size: 12px; padding: 4px 8px; border-radius: 6px; margin-bottom: 4px; }
  .e.error { background: rgba(255,77,77,0.15); color: var(--bad); }
  .e.warn { background: rgba(255,180,0,0.12); color: var(--warn-2); }
  .err-box { background: rgba(255,77,77,0.15); color: var(--bad); padding: 12px; border-radius: 8px; }
  .muted { color: var(--t-7); padding: 20px; }
</style>
