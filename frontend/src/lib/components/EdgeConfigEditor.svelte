<script lang="ts">
  import { onMount } from 'svelte';
  import { tr } from '$lib/i18n';
  import { apiFetch } from '$lib/api';
  import { showToast } from '$lib/components/Toast.svelte';

  let { deploymentId, onClose } = $props<{ deploymentId: number; onClose: () => void }>();

  type Cfg = Record<string, unknown>;

  let cfg = $state<Cfg>({});
  let keys = $state<string[]>([]);
  let redacted = $state<string[]>([]);
  let loading = $state(true);
  let saving = $state(false);
  let error = $state('');
  // dirty holds ONLY what the operator changed. It is what gets sent, so a
  // field this build has never heard of is never included and therefore never
  // overwritten — the panel merges a patch, it does not replace the document.
  let dirty = $state<Cfg>({});
  let rawOpen = $state(false);
  let rawText = $state('');

  // Field groups. This list is a convenience for laying the form out, NOT a
  // schema: anything the Worker returns that is not named here still appears,
  // under "other", so a Worker newer than this panel stays fully editable.
  // labelKey carries the FULL translation key, not a suffix to compose.
  // 'edgecfg.group.' + g.id would read fine and be invisible to the i18n guard,
  // which scans for literal tr('…') keys — the composed keys would look like
  // orphaned catalogue entries and the prefix like an undefined one. labelKey is
  // the convention the sidebar and the endpoint presets already use.
  const groups: { id: string; labelKey: string; fields: string[] }[] = [
    { id: 'identity', labelKey: 'edgecfg.group.identity', fields: ['subTitle', 'remarkPrefix', 'remarkStyle', 'vlessUUID', 'trojanPassword', 'wsPathSalt'] },
    { id: 'transport', labelKey: 'edgecfg.group.transport', fields: ['protocols', 'ports', 'httpsPorts', 'httpPorts', 'fingerprint', 'enableIPv6', 'enableTFO'] },
    { id: 'cleanip', labelKey: 'edgecfg.group.cleanip', fields: ['cleanIPs', 'cleanIPSources', 'cleanIPRefresh', 'cleanIPRandomCount', 'bestPingInterval'] },
    { id: 'fronting', labelKey: 'edgecfg.group.fronting', fields: ['customDomain', 'customCdnHost', 'customCdnSni', 'customCdnAddrs', 'fallbackHost'] },
    { id: 'evasion', labelKey: 'edgecfg.group.evasion', fields: ['fragment', 'udpNoises', 'enableECH', 'echServerName'] },
    { id: 'relay', labelKey: 'edgecfg.group.relay', fields: ['proxyIPMode', 'proxyIPs', 'nat64Prefixes', 'chainProxy'] },
    { id: 'dns', labelKey: 'edgecfg.group.dns', fields: ['remoteDNS', 'localDNS', 'dohUpstream', 'antiSanctionDNS', 'fakeDNS'] },
    { id: 'routing', labelKey: 'edgecfg.group.routing', fields: ['routing'] },
    { id: 'warp', labelKey: 'edgecfg.group.warp', fields: ['warp'] },
    { id: 'feed', labelKey: 'edgecfg.group.feed', fields: ['backend', 'externalSubs', 'feedPullURL', 'feedPullToken'] },
    { id: 'notify', labelKey: 'edgecfg.group.notify', fields: ['telegramBotToken', 'telegramUserID'] },
    { id: 'maintenance', labelKey: 'edgecfg.group.maintenance', fields: ['autoUpdateCheck', 'updateRepo', 'logLevel', 'version'] }
  ];

  const known = new Set(groups.flatMap((g) => g.fields));
  let otherKeys = $derived(keys.filter((k) => !known.has(k)));

  async function load() {
    loading = true;
    error = '';
    try {
      const res = await apiFetch<{ config: Cfg; keys: string[]; redacted: string[] }>(
        `/admin/edge/deployments/${deploymentId}/config`
      );
      cfg = res.config ?? {};
      keys = res.keys ?? [];
      redacted = res.redacted ?? [];
      dirty = {};
      rawText = JSON.stringify(cfg, null, 2);
    } catch (e: any) {
      error = e.message || tr('edgecfg.failed_to_load');
    } finally {
      loading = false;
    }
  }
  onMount(load);

  function kind(k: string): 'bool' | 'number' | 'list' | 'json' | 'text' {
    const v = cfg[k];
    if (typeof v === 'boolean') return 'bool';
    if (typeof v === 'number') return 'number';
    if (Array.isArray(v)) return v.every((x) => typeof x !== 'object' || x === null) ? 'list' : 'json';
    if (v !== null && typeof v === 'object') return 'json';
    return 'text';
  }

  function shown(k: string): string {
    const v = k in dirty ? dirty[k] : cfg[k];
    const t = kind(k);
    if (t === 'list') return (v as unknown[])?.join(', ') ?? '';
    if (t === 'json') return JSON.stringify(v, null, 2);
    return v == null ? '' : String(v);
  }

  function edit(k: string, raw: string) {
    const t = kind(k);
    if (t === 'number') {
      const n = Number(raw);
      dirty[k] = Number.isFinite(n) ? n : 0;
    } else if (t === 'list') {
      // Numeric lists stay numeric: ports sent as strings are a value the
      // Worker rejects, and the rejection reads as "the panel ignored me".
      const parts = raw.split(',').map((p) => p.trim()).filter(Boolean);
      const numeric = Array.isArray(cfg[k]) && (cfg[k] as unknown[]).every((x) => typeof x === 'number');
      dirty[k] = numeric ? parts.map(Number).filter((n) => Number.isFinite(n)) : parts;
    } else {
      dirty[k] = raw;
    }
    dirty = { ...dirty };
  }

  function editBool(k: string, v: boolean) {
    dirty[k] = v;
    dirty = { ...dirty };
  }

  function editJSON(k: string, raw: string) {
    try {
      dirty[k] = JSON.parse(raw);
      dirty = { ...dirty };
    } catch {
      // Left for save() to report, so a half-typed object does not spam a toast
      // on every keystroke.
      dirty[k] = raw;
      dirty = { ...dirty };
    }
  }

  let dirtyCount = $derived(Object.keys(dirty).length);

  async function save() {
    if (dirtyCount === 0) return;
    // A string sitting where the Worker expects an object means the operator is
    // mid-edit in a JSON box. Saving it would be rejected by the Worker with a
    // message about the field rather than about the typo.
    for (const k of Object.keys(dirty)) {
      if (kind(k) === 'json' && typeof dirty[k] === 'string') {
        showToast(tr('edgecfg.not_valid_json', { field: k }), 'error');
        return;
      }
    }
    saving = true;
    try {
      const res = await apiFetch<{ config: Cfg; changed: string[] }>(
        `/admin/edge/deployments/${deploymentId}/config`,
        { method: 'PUT', body: JSON.stringify(dirty) }
      );
      cfg = res.config ?? cfg;
      rawText = JSON.stringify(cfg, null, 2);
      dirty = {};
      showToast(tr('edgecfg.saved', { count: res.changed?.length ?? 0 }), 'success');
    } catch (e: any) {
      showToast(e.message || tr('edgecfg.failed_to_save'), 'error');
    } finally {
      saving = false;
    }
  }

  async function saveRaw() {
    let parsed: Cfg;
    try {
      parsed = JSON.parse(rawText);
    } catch {
      showToast(tr('edgecfg.raw_not_valid_json'), 'error');
      return;
    }
    saving = true;
    try {
      const res = await apiFetch<{ config: Cfg }>(`/admin/edge/deployments/${deploymentId}/config`, {
        method: 'PUT',
        body: JSON.stringify(parsed)
      });
      cfg = res.config ?? cfg;
      rawText = JSON.stringify(cfg, null, 2);
      dirty = {};
      showToast(tr('edgecfg.saved_raw'), 'success');
    } catch (e: any) {
      showToast(e.message || tr('edgecfg.failed_to_save'), 'error');
    } finally {
      saving = false;
    }
  }
</script>

<div class="cfg" data-testid="edge-config-editor">
  <div class="cfg-head">
    <h4>{tr('edgecfg.title')}</h4>
    <div class="cfg-head-actions">
      <button class="btn sm" onclick={load} disabled={loading || saving}>{tr('edgecfg.reload')}</button>
      <button class="btn sm" onclick={onClose}>{tr('edgecfg.close')}</button>
    </div>
  </div>

  {#if loading}
    <p class="muted">{tr('edgecfg.loading')}</p>
  {:else if error}
    <p class="err">{error}</p>
  {:else}
    <p class="hint">{tr('edgecfg.explainer')}</p>

    {#each groups as g}
      {@const present = g.fields.filter((f) => keys.includes(f))}
      {#if present.length > 0}
        <details open={g.id === 'identity'}>
          <summary>{tr(g.labelKey)}</summary>
          <div class="grid">
            {#each present as k}
              <label class:wide={kind(k) === 'json'}>
                <span class="fname">{k}{#if redacted.includes(k)}<em class="sec">{tr('edgecfg.secret')}</em>{/if}</span>
                {#if kind(k) === 'bool'}
                  <input
                    type="checkbox"
                    checked={Boolean(k in dirty ? dirty[k] : cfg[k])}
                    onchange={(e) => editBool(k, e.currentTarget.checked)}
                  />
                {:else if kind(k) === 'json'}
                  <textarea rows="5" value={shown(k)} oninput={(e) => editJSON(k, e.currentTarget.value)}></textarea>
                {:else}
                  <input value={shown(k)} oninput={(e) => edit(k, e.currentTarget.value)} />
                {/if}
                {#if kind(k) === 'list'}<em class="fhint">{tr('edgecfg.comma_separated')}</em>{/if}
              </label>
            {/each}
          </div>
        </details>
      {/if}
    {/each}

    {#if otherKeys.length > 0}
      <details>
        <summary>{tr('edgecfg.group.other', { count: otherKeys.length })}</summary>
        <p class="hint">{tr('edgecfg.other_explainer')}</p>
        <div class="grid">
          {#each otherKeys as k}
            <label class:wide={kind(k) === 'json'}>
              <span class="fname">{k}</span>
              {#if kind(k) === 'bool'}
                <input type="checkbox" checked={Boolean(k in dirty ? dirty[k] : cfg[k])} onchange={(e) => editBool(k, e.currentTarget.checked)} />
              {:else if kind(k) === 'json'}
                <textarea rows="4" value={shown(k)} oninput={(e) => editJSON(k, e.currentTarget.value)}></textarea>
              {:else}
                <input value={shown(k)} oninput={(e) => edit(k, e.currentTarget.value)} />
              {/if}
            </label>
          {/each}
        </div>
      </details>
    {/if}

    <div class="cfg-foot">
      <button class="btn primary" onclick={save} disabled={saving || dirtyCount === 0} data-testid="edge-config-save">
        {saving ? tr('edgecfg.saving') : tr('edgecfg.save_n', { count: dirtyCount })}
      </button>
      <button class="btn sm" onclick={() => (rawOpen = !rawOpen)}>{tr('edgecfg.raw_toggle')}</button>
    </div>

    {#if rawOpen}
      <p class="hint">{tr('edgecfg.raw_explainer')}</p>
      <textarea class="raw" rows="16" bind:value={rawText}></textarea>
      <button class="btn sm danger" onclick={saveRaw} disabled={saving}>{tr('edgecfg.save_raw')}</button>
    {/if}
  {/if}
</div>

<style>
  .cfg { margin-top: 12px; padding: 12px; border: 1px solid var(--ln-4); border-radius: 10px; background: var(--bg); }
  .cfg-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
  .cfg-head h4 { margin: 0; font-size: 14px; }
  .cfg-head-actions { display: flex; gap: 6px; }
  .hint { color: var(--t-5); font-size: 12px; line-height: 1.6; margin: 8px 0; }
  .muted { color: var(--t-7); font-size: 13px; }
  .err { color: var(--bad-3); font-size: 13px; }
  details { border-top: 1px solid var(--ln-3); padding: 8px 0; }
  summary { cursor: pointer; font-size: 13px; color: var(--t-2); }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; margin-top: 10px; }
  label { display: flex; flex-direction: column; gap: 4px; font-size: 12px; color: var(--t-2); }
  label.wide { grid-column: 1 / -1; }
  .fname { font-family: ui-monospace, monospace; font-size: 11px; color: var(--t-5); }
  .sec { color: var(--warn); font-style: normal; margin-inline-start: 6px; }
  .fhint { color: var(--t-8); font-size: 11px; font-style: normal; }
  input, textarea { padding: 7px 9px; border-radius: 6px; border: 1px solid var(--ln-5); background: var(--bg-deep); color: var(--fg); font-size: 13px; }
  input[type='checkbox'] { width: 16px; height: 16px; }
  textarea { font-family: ui-monospace, monospace; font-size: 12px; }
  .raw { width: 100%; margin-bottom: 8px; }
  .cfg-foot { display: flex; gap: 8px; align-items: center; margin-top: 12px; }
</style>
