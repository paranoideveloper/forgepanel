<script lang="ts">
	import { tr } from '$lib/i18n';
  import { onMount } from 'svelte';
  import { apiFetch } from '$lib/api';
  import { showToast } from '$lib/components/Toast.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import QRCode from '$lib/components/QRCode.svelte';
  import InboundForm from '$lib/components/InboundForm.svelte';
  import HostsEditor from '$lib/components/HostsEditor.svelte';

  interface Row {
    id: number; remark: string; protocol: string; port: number; enabled: boolean;
    not_serving_reason?: string; not_serving_since?: string;
    reachable?: boolean;
    node?: any;
  }

  let rows = $state<Row[]>([]);
  let loading = $state(true);
  let creating = $state(false);
  let editRow = $state<Row | null>(null);
  let selected = $state<Set<number>>(new Set());

  function toggleSel(id: number) {
    const s = new Set(selected); if (s.has(id)) s.delete(id); else s.add(id); selected = s;
  }
  function toggleAll() {
    selected = selected.size === rows.length ? new Set() : new Set(rows.map(r => r.id));
  }
  async function bulk(action: 'enable' | 'disable' | 'delete') {
    if (selected.size === 0) return;
    if (action === 'delete' && !confirm(tr('inbounds.delete_size_inbound_s', { size: selected.size }))) return;
    try {
      await apiFetch('/admin/inbounds/bulk', { method: 'POST', body: JSON.stringify({ action, ids: [...selected] }) });
      showToast(tr('inbounds.action_size_inbound_s', { action, size: selected.size }), 'success');
      selected = new Set();
      load();
    } catch (e: any) { showToast(e.message || tr('inbounds.bulk_action_failed'), 'error'); }
  }
  let verifyResults = $state<Record<number, { pass: boolean; unprovable?: boolean; latency?: number; detail?: string }>>({});

  let cfgOpen = $state(false);
  let cfgKind = $state('');
  let cfgUri = $state('');
  let cfgText = $state('');
  let cfgTitle = $state('');

  // Paste-Anything importer
  let importing = $state(false);
  let importText = $state('');
  let importBusy = $state(false);

  async function runImport() {
    if (!importText.trim()) return;
    importBusy = true;
    try {
      const res = await apiFetch<{ count: number; nodes: any[]; errors?: string[] }>('/import', {
        method: 'POST', body: JSON.stringify({ text: importText }),
      });
      if (!res.count) { showToast(tr('inbounds.nothing_recognized_to_import'), 'error'); return; }
      let ok = 0;
      for (const node of res.nodes) {
        try { await apiFetch('/admin/inbounds', { method: 'POST', body: JSON.stringify(node) }); ok++; } catch (_) {}
      }
      showToast(tr('inbounds.imported_ok_count_as_inbounds', { ok, count: res.count }), ok ? 'success' : 'error');
      importText = ''; importing = false; load();
    } catch (e: any) {
      showToast(e.message || tr('inbounds.import_failed'), 'error');
    } finally {
      importBusy = false;
    }
  }

  async function load() {
    loading = true;
    try {
      rows = await apiFetch<Row[]>('/admin/inbounds');
    } catch (e: any) {
      showToast(e.message || tr('inbounds.failed_to_load_inbounds'), 'error');
    } finally {
      loading = false;
    }
  }

  function onSaved() {
    creating = false;
    editRow = null;
    load();
  }

  function edit(r: Row) {
    creating = false;
    editRow = editRow?.id === r.id ? null : r;
  }

  async function quickReality() {
    try {
      await apiFetch('/admin/inbounds/reality-quickstart', { method: 'POST', body: JSON.stringify({}) });
      showToast(tr('inbounds.reality_inbound_created'), 'success');
      load();
    } catch (e: any) {
      showToast(e.message || tr('inbounds.quickstart_failed'), 'error');
    }
  }

  async function showConfig(r: Row) {
    try {
      const res = await apiFetch<{ kind: string; uri?: string; config?: string; filename?: string }>(`/admin/inbounds/${r.id}/config`);
      cfgKind = res.kind;
      cfgUri = res.uri || '';
      cfgText = res.config || res.uri || '';
      cfgTitle = `${r.remark || r.protocol} · #${r.id}`;
      cfgOpen = true;
    } catch (e: any) {
      showToast(e.message || tr('inbounds.failed_to_load_config'), 'error');
    }
  }

  // WireGuard/AmneziaWG are UDP protocols with no stream transport, and
  // Hysteria2/TUIC ride QUIC (UDP) — showing the xray `transport.network` (which
  // defaults to "tcp") for them is misleading, so report their real wire protocol.
  function transportLabel(r: Row): string {
    const p = (r as any).protocol as string;
    if (p === 'wireguard' || p === 'amneziawg') return 'udp';
    if (p === 'hysteria2' || p === 'tuic') return 'udp/quic';
    return (r as any).node?.transport?.network || '—';
  }

  async function verify(r: Row) {
    verifyResults[r.id] = { pass: false, detail: 'verifying…' } as any;
    try {
      const res = await apiFetch<{ pass: boolean; unprovable?: boolean; latency_ms?: number; finding?: { detail?: string } }>(`/admin/inbounds/${r.id}/verify`, { method: 'POST' });
      verifyResults[r.id] = { pass: res.pass, unprovable: res.unprovable, latency: res.latency_ms, detail: res.finding?.detail };
      if (res.unprovable) showToast(res.finding?.detail || tr('inbounds.cannot_verify_on_loopback_test_from'), 'info');
      else showToast(res.pass ? tr('inbounds.verify_ok_ms', { ms: res.latency_ms }) : tr('inbounds.verify_failed_detail', { detail: res.finding?.detail || '' }), res.pass ? 'success' : 'error');
    } catch (e: any) {
      verifyResults[r.id] = { pass: false, detail: e.message };
      showToast(e.message || tr('inbounds.verify_failed'), 'error');
    }
  }

  async function clone(r: Row) {
    try { await apiFetch(`/admin/inbounds/${r.id}/clone`, { method: 'POST' }); showToast(tr('inbounds.cloned'), 'success'); load(); }
    catch (e: any) { showToast(e.message || tr('inbounds.clone_failed'), 'error'); }
  }
  async function toggle(r: Row) {
    try { await apiFetch(`/admin/inbounds/${r.id}/toggle`, { method: 'POST' }); load(); }
    catch (e: any) { showToast(e.message || tr('inbounds.toggle_failed'), 'error'); }
  }
  async function del(r: Row) {
    if (!confirm(tr('inbounds.delete_inbound_p1_port', { p1: r.remark || r.protocol, port: r.port }))) return;
    try { await apiFetch(`/admin/inbounds/${r.id}`, { method: 'DELETE' }); showToast(tr('inbounds.deleted'), 'info'); load(); }
    catch (e: any) { showToast(e.message || tr('inbounds.delete_failed'), 'error'); }
  }

  function copy(text: string) {
    navigator.clipboard.writeText(text).then(() => showToast(tr('inbounds.copied'), 'success'));
  }

  onMount(load);
</script>

<div class="head">
  <h2>{tr('inbounds.inbounds')}</h2>
  <div class="actions">
    <button class="ghost" data-testid="import-toggle" onclick={() => importing = !importing}>{tr('inbounds.import')}</button>
    <button class="ghost" data-testid="quick-reality" onclick={quickReality}>{tr('inbounds.one_click_reality')}</button>
    <button class="primary" data-testid="create-inbound" onclick={() => creating = !creating}>
      {creating ? tr('inbounds.close') : tr('inbounds.create_inbound_2')}
    </button>
  </div>
</div>

{#if importing}
  <div class="card" data-testid="import-panel">
    <h3>{tr('inbounds.paste_anything_links_a_subscription_base64')}</h3>
    <textarea data-testid="import-text" bind:value={importText} rows="4"
      placeholder={tr('inbounds.vless_10_vmess_10_https_host')}></textarea>
    <button class="primary" data-testid="import-run" onclick={runImport} disabled={importBusy}>
      {importBusy ? tr('inbounds.importing') : tr('inbounds.parse_create_inbounds')}
    </button>
  </div>
{/if}

{#if creating}
  <div class="card creator" data-testid="inbound-creator">
    <h3>{tr('inbounds.create_a_new_inbound')}</h3>
    <InboundForm onSaved={onSaved} />
  </div>
{/if}

{#if editRow}
  <div class="card creator" data-testid="inbound-editor">
    <h3>{tr('inbounds.edit_inbound', { id: editRow.id, p2: editRow.remark || editRow.protocol })}</h3>
    {#key editRow.id}
      <InboundForm onSaved={onSaved} initial={editRow.node} editId={editRow.id} />
    {/key}
    <h4>{tr('inbounds.endpoints')}</h4>
    {#key editRow.id}
      <HostsEditor inboundId={editRow.id} />
    {/key}
  </div>
{/if}

<div class="card">
  {#if loading}
    <p class="muted">{tr('inbounds.loading')}</p>
  {:else if rows.length === 0}
    <p class="muted" data-testid="inbounds-empty">{tr('inbounds.no_inbounds_yet_click')} <strong>{tr('inbounds.create_inbound')}</strong> {tr('inbounds.or')} <strong>{tr('inbounds.one_click_reality')}</strong> {tr('inbounds.to_add_one')}</p>
  {:else}
    {#if selected.size > 0}
      <div class="bulkbar" data-testid="bulk-bar">
        <span>{tr('inbounds.selected', { size: selected.size })}</span>
        <button class="sm" data-testid="bulk-enable" onclick={() => bulk('enable')}>{tr('inbounds.enable')}</button>
        <button class="sm" onclick={() => bulk('disable')}>{tr('inbounds.disable')}</button>
        <button class="sm danger" data-testid="bulk-delete" onclick={() => bulk('delete')}>{tr('inbounds.delete')}</button>
      </div>
    {/if}
    <div class="table-scroll">
    <table data-testid="inbounds-table">
      <thead>
        <tr><th><input type="checkbox" data-testid="select-all" checked={selected.size === rows.length && rows.length > 0} onchange={toggleAll} /></th><th>#</th><th>{tr('inbounds.remark')}</th><th>{tr('inbounds.protocol')}</th><th>{tr('inbounds.transport')}</th><th>{tr('inbounds.security')}</th><th>{tr('inbounds.port')}</th><th>{tr('inbounds.status')}</th><th>{tr('inbounds.verify')}</th><th>{tr('inbounds.actions')}</th></tr>
      </thead>
      <tbody>
        {#each rows as r (r.id)}
          <tr data-testid="inbound-row" data-proto={r.protocol}>
            <td><input type="checkbox" checked={selected.has(r.id)} onchange={() => toggleSel(r.id)} /></td>
            <td>{r.id}</td>
            <td><strong>{r.remark || '—'}</strong></td>
            <td><span class="proto">{r.protocol}</span></td>
            <td>{transportLabel(r)}</td>
            <td>{r.node?.security?.type || 'none'}</td>
            <td>{r.port}</td>
            <td>
              <span class="badge {r.enabled ? 'ok' : 'off'}">{r.enabled ? tr('inbounds.enabled') : tr('inbounds.disabled')}</span>
              <!-- An inbound no core could serve is left OUT of the running
                   config so one bad inbound cannot take the rest down. Without
                   this badge the operator sees "Enabled", the inbound carries no
                   traffic, and nothing anywhere says why. -->
              {#if r.enabled && r.not_serving_reason}
                <span class="badge err" data-testid="not-serving"
                      title="This inbound is enabled but is NOT in the running configuration: {r.not_serving_reason}{r.not_serving_since ? tr('inbounds.since') + new Date(r.not_serving_since).toLocaleString() + ')' : ''}">
                  {tr('inbounds.not_serving')}
                </span>
              {/if}
              {#if r.enabled && r.reachable === false}
                <span class="badge err" data-testid="fw-blocked" title="Port {r.port} is not allowed in the host firewall (ufw), so external clients are dropped even though Verify passes on loopback. A native install running as root opens it automatically; inside Docker or behind a VPS provider firewall the panel cannot, so allow it yourself: ufw allow {r.port} (and in your provider's firewall panel).">{tr('inbounds.firewall')}</span>
              {/if}
            </td>
            <td>
              {#if verifyResults[r.id]}
                <span class="badge {verifyResults[r.id].unprovable ? 'neutral' : verifyResults[r.id].pass ? 'ok' : 'err'}" title={verifyResults[r.id].detail || ''}>
                  {verifyResults[r.id].unprovable ? '— n/a' : verifyResults[r.id].pass ? `✓ ${verifyResults[r.id].latency}ms` : '✗'}
                </span>
              {:else}<span class="muted">—</span>{/if}
            </td>
            <td class="row-actions">
              <button class="sm" data-testid="config-btn" onclick={() => showConfig(r)}>{tr('inbounds.config')}</button>
              <button class="sm" data-testid="edit-btn" onclick={() => edit(r)}>{tr('inbounds.edit')}</button>
              <button class="sm" onclick={() => verify(r)}>{tr('inbounds.verify')}</button>
              <button class="sm" onclick={() => clone(r)}>{tr('inbounds.clone')}</button>
              <button class="sm" onclick={() => toggle(r)}>{r.enabled ? tr('inbounds.disable_toggle') : tr('inbounds.enable_toggle')}</button>
              <button class="sm danger" onclick={() => del(r)}>{tr('inbounds.delete')}</button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    </div>
  {/if}
</div>

<Modal title={tr('inbounds.config_3') + cfgTitle} isOpen={cfgOpen} onClose={() => cfgOpen = false}>
  {#if cfgKind === 'uri'}
    <div class="cfg">
      <span class="lbl">{tr('inbounds.client_link')}</span>
      <div class="uri-row">
        <code data-testid="config-uri">{cfgUri}</code>
        <button class="sm" onclick={() => copy(cfgUri)}>{tr('inbounds.copy')}</button>
      </div>
      {#if cfgUri}<div class="qr"><QRCode value={cfgUri} size={200} /></div>{/if}
    </div>
  {:else}
    <div class="cfg">
      <span class="lbl">{tr('inbounds.config_2', { cfgKind })}</span>
      <pre data-testid="config-uri">{cfgText}</pre>
      <button class="sm" onclick={() => copy(cfgText)}>{tr('inbounds.copy')}</button>
    </div>
  {/if}
</Modal>

<style>
  .head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
  .head h2 { margin: 0; font-size: 20px; }
  .actions { display: flex; gap: 10px; }
  .card { background: #141A24; border: 1px solid rgba(255,255,255,0.08); border-radius: 14px; padding: 20px; margin-bottom: 20px; }
  .card h3 { margin: 0 0 16px; font-size: 15px; }
  .primary { background: #FF7A1A; color: #1a1204; border: none; font-weight: 700; padding: 10px 16px; border-radius: 8px; cursor: pointer; }
  .ghost { background: transparent; color: #FF9A4A; border: 1px solid rgba(255,122,26,0.4); padding: 10px 16px; border-radius: 8px; cursor: pointer; }
  /* On a phone the row is wider than the screen; scroll it inside the card
     instead of pushing the whole page sideways. */
  .table-scroll { overflow-x: auto; -webkit-overflow-scrolling: touch; margin: 0 -4px; }
  table { width: 100%; min-width: 720px; border-collapse: collapse; }
  th, td { padding: 11px 10px; text-align: start; border-bottom: 1px solid rgba(255,255,255,0.07); font-size: 13px; white-space: nowrap; }
  th { color: rgba(255,255,255,0.55); font-weight: 600; font-size: 12px; }
  .proto { background: rgba(255,122,26,0.12); color: #FF9A4A; padding: 2px 8px; border-radius: 6px; font-size: 12px; }
  .badge { padding: 3px 9px; border-radius: 12px; font-size: 11px; font-weight: 600; }
  .badge.ok { background: rgba(39,209,124,0.15); color: #27D17C; }
  .badge.off { background: rgba(255,255,255,0.1); color: rgba(255,255,255,0.6); }
  .badge.err { background: rgba(255,77,77,0.15); color: #FF4D4D; }
  .badge.neutral { background: rgba(255,255,255,0.1); color: rgba(255,255,255,0.65); }
  .row-actions { display: flex; gap: 6px; flex-wrap: wrap; }
  .sm { padding: 5px 10px; font-size: 12px; border-radius: 6px; background: #1A2230; color: #fff; border: 1px solid rgba(255,255,255,0.1); cursor: pointer; }
  .sm.danger { background: rgba(255,77,77,0.15); color: #FF4D4D; border-color: rgba(255,77,77,0.3); }
  .muted { color: rgba(255,255,255,0.45); }
  .bulkbar { display: flex; align-items: center; gap: 10px; padding: 8px 12px; margin-bottom: 12px; background: rgba(255,122,26,0.1); border: 1px solid rgba(255,122,26,0.3); border-radius: 8px; font-size: 13px; }
  .cfg { display: flex; flex-direction: column; gap: 10px; }
  .cfg .lbl { font-size: 12px; color: rgba(255,255,255,0.6); }
  textarea { width: 100%; box-sizing: border-box; background: #0F1420; border: 1px solid rgba(255,255,255,0.12); color: #fff; padding: 10px; border-radius: 8px; font-family: monospace; font-size: 12px; margin-bottom: 10px; }
  .uri-row { display: flex; gap: 8px; align-items: center; }
  .uri-row code { flex: 1; background: #0F1420; padding: 10px; border-radius: 8px; font-size: 12px; word-break: break-all; color: #27D17C; }
  .qr { display: flex; justify-content: center; padding: 10px; background: #fff; border-radius: 10px; }
  pre { background: #0F1420; padding: 12px; border-radius: 8px; overflow-x: auto; font-size: 12px; color: #27D17C; white-space: pre-wrap; word-break: break-all; }
</style>
