<script lang="ts">
  import { onMount } from 'svelte';
  import { apiFetch } from '$lib/api';
  import { showToast } from '$lib/components/Toast.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import QRCode from '$lib/components/QRCode.svelte';
  import InboundForm from '$lib/components/InboundForm.svelte';

  interface Row {
    id: number; remark: string; protocol: string; port: number; enabled: boolean;
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
    if (action === 'delete' && !confirm(`Delete ${selected.size} inbound(s)?`)) return;
    try {
      await apiFetch('/admin/inbounds/bulk', { method: 'POST', body: JSON.stringify({ action, ids: [...selected] }) });
      showToast(`${action} ${selected.size} inbound(s)`, 'success');
      selected = new Set();
      load();
    } catch (e: any) { showToast(e.message || 'bulk action failed', 'error'); }
  }
  let verifyResults = $state<Record<number, { pass: boolean; latency?: number; detail?: string }>>({});

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
      if (!res.count) { showToast('Nothing recognized to import', 'error'); return; }
      let ok = 0;
      for (const node of res.nodes) {
        try { await apiFetch('/admin/inbounds', { method: 'POST', body: JSON.stringify(node) }); ok++; } catch (_) {}
      }
      showToast(`Imported ${ok}/${res.count} as inbounds`, ok ? 'success' : 'error');
      importText = ''; importing = false; load();
    } catch (e: any) {
      showToast(e.message || 'import failed', 'error');
    } finally {
      importBusy = false;
    }
  }

  async function load() {
    loading = true;
    try {
      rows = await apiFetch<Row[]>('/admin/inbounds');
    } catch (e: any) {
      showToast(e.message || 'failed to load inbounds', 'error');
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
      showToast('REALITY inbound created', 'success');
      load();
    } catch (e: any) {
      showToast(e.message || 'quickstart failed', 'error');
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
      showToast(e.message || 'failed to load config', 'error');
    }
  }

  async function verify(r: Row) {
    verifyResults[r.id] = { pass: false, detail: 'verifying…' } as any;
    try {
      const res = await apiFetch<{ pass: boolean; latency_ms?: number; finding?: { detail?: string } }>(`/admin/inbounds/${r.id}/verify`, { method: 'POST' });
      verifyResults[r.id] = { pass: res.pass, latency: res.latency_ms, detail: res.finding?.detail };
      showToast(res.pass ? `Verify OK (${res.latency_ms}ms)` : `Verify failed: ${res.finding?.detail || ''}`, res.pass ? 'success' : 'error');
    } catch (e: any) {
      verifyResults[r.id] = { pass: false, detail: e.message };
      showToast(e.message || 'verify failed', 'error');
    }
  }

  async function clone(r: Row) {
    try { await apiFetch(`/admin/inbounds/${r.id}/clone`, { method: 'POST' }); showToast('Cloned', 'success'); load(); }
    catch (e: any) { showToast(e.message || 'clone failed', 'error'); }
  }
  async function toggle(r: Row) {
    try { await apiFetch(`/admin/inbounds/${r.id}/toggle`, { method: 'POST' }); load(); }
    catch (e: any) { showToast(e.message || 'toggle failed', 'error'); }
  }
  async function del(r: Row) {
    if (!confirm(`Delete inbound "${r.remark || r.protocol}" (:${r.port})?`)) return;
    try { await apiFetch(`/admin/inbounds/${r.id}`, { method: 'DELETE' }); showToast('Deleted', 'info'); load(); }
    catch (e: any) { showToast(e.message || 'delete failed', 'error'); }
  }

  function copy(text: string) {
    navigator.clipboard.writeText(text).then(() => showToast('Copied', 'success'));
  }

  onMount(load);
</script>

<div class="head">
  <h2>Inbounds</h2>
  <div class="actions">
    <button class="ghost" data-testid="import-toggle" onclick={() => importing = !importing}>Import</button>
    <button class="ghost" data-testid="quick-reality" onclick={quickReality}>One-click REALITY</button>
    <button class="primary" data-testid="create-inbound" onclick={() => creating = !creating}>
      {creating ? 'Close' : '+ Create Inbound'}
    </button>
  </div>
</div>

{#if importing}
  <div class="card" data-testid="import-panel">
    <h3>Paste anything — links, a subscription, base64, or JSON</h3>
    <textarea data-testid="import-text" bind:value={importText} rows="4"
      placeholder="vless://…&#10;vmess://…&#10;https://host/sub/token&#10;(base64 or clash/sing-box JSON)"></textarea>
    <button class="primary" data-testid="import-run" onclick={runImport} disabled={importBusy}>
      {importBusy ? 'Importing…' : 'Parse & create inbounds'}
    </button>
  </div>
{/if}

{#if creating}
  <div class="card creator" data-testid="inbound-creator">
    <h3>Create a new inbound</h3>
    <InboundForm onSaved={onSaved} />
  </div>
{/if}

{#if editRow}
  <div class="card creator" data-testid="inbound-editor">
    <h3>Edit inbound #{editRow.id} — {editRow.remark || editRow.protocol}</h3>
    {#key editRow.id}
      <InboundForm onSaved={onSaved} initial={editRow.node} editId={editRow.id} />
    {/key}
  </div>
{/if}

<div class="card">
  {#if loading}
    <p class="muted">Loading…</p>
  {:else if rows.length === 0}
    <p class="muted" data-testid="inbounds-empty">No inbounds yet. Click <strong>Create Inbound</strong> or <strong>One-click REALITY</strong> to add one.</p>
  {:else}
    {#if selected.size > 0}
      <div class="bulkbar" data-testid="bulk-bar">
        <span>{selected.size} selected</span>
        <button class="sm" data-testid="bulk-enable" onclick={() => bulk('enable')}>Enable</button>
        <button class="sm" onclick={() => bulk('disable')}>Disable</button>
        <button class="sm danger" data-testid="bulk-delete" onclick={() => bulk('delete')}>Delete</button>
      </div>
    {/if}
    <table data-testid="inbounds-table">
      <thead>
        <tr><th><input type="checkbox" data-testid="select-all" checked={selected.size === rows.length && rows.length > 0} onchange={toggleAll} /></th><th>#</th><th>Remark</th><th>Protocol</th><th>Transport</th><th>Security</th><th>Port</th><th>Status</th><th>Verify</th><th>Actions</th></tr>
      </thead>
      <tbody>
        {#each rows as r (r.id)}
          <tr data-testid="inbound-row" data-proto={r.protocol}>
            <td><input type="checkbox" checked={selected.has(r.id)} onchange={() => toggleSel(r.id)} /></td>
            <td>{r.id}</td>
            <td><strong>{r.remark || '—'}</strong></td>
            <td><span class="proto">{r.protocol}</span></td>
            <td>{r.node?.transport?.network || '—'}</td>
            <td>{r.node?.security?.type || 'none'}</td>
            <td>{r.port}</td>
            <td>
              <span class="badge {r.enabled ? 'ok' : 'off'}">{r.enabled ? 'Enabled' : 'Disabled'}</span>
              {#if r.enabled && r.reachable === false}
                <span class="badge err" data-testid="fw-blocked" title="This port is blocked by the host firewall (ufw). External clients — a phone — cannot reach it even though Verify passes on loopback. Open it: ufw allow {r.port}">🔥 firewall</span>
              {/if}
            </td>
            <td>
              {#if verifyResults[r.id]}
                <span class="badge {verifyResults[r.id].pass ? 'ok' : 'err'}" title={verifyResults[r.id].detail || ''}>
                  {verifyResults[r.id].pass ? `✓ ${verifyResults[r.id].latency}ms` : '✗'}
                </span>
              {:else}<span class="muted">—</span>{/if}
            </td>
            <td class="row-actions">
              <button class="sm" data-testid="config-btn" onclick={() => showConfig(r)}>Config</button>
              <button class="sm" data-testid="edit-btn" onclick={() => edit(r)}>Edit</button>
              <button class="sm" onclick={() => verify(r)}>Verify</button>
              <button class="sm" onclick={() => clone(r)}>Clone</button>
              <button class="sm" onclick={() => toggle(r)}>{r.enabled ? 'Disable' : 'Enable'}</button>
              <button class="sm danger" onclick={() => del(r)}>Delete</button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

<Modal title={'Config · ' + cfgTitle} isOpen={cfgOpen} onClose={() => cfgOpen = false}>
  {#if cfgKind === 'uri'}
    <div class="cfg">
      <span class="lbl">Client link</span>
      <div class="uri-row">
        <code data-testid="config-uri">{cfgUri}</code>
        <button class="sm" onclick={() => copy(cfgUri)}>Copy</button>
      </div>
      {#if cfgUri}<div class="qr"><QRCode value={cfgUri} size={200} /></div>{/if}
    </div>
  {:else}
    <div class="cfg">
      <span class="lbl">{cfgKind} config</span>
      <pre data-testid="config-uri">{cfgText}</pre>
      <button class="sm" onclick={() => copy(cfgText)}>Copy</button>
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
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 11px 10px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.07); font-size: 13px; }
  th { color: rgba(255,255,255,0.55); font-weight: 600; font-size: 12px; }
  .proto { background: rgba(255,122,26,0.12); color: #FF9A4A; padding: 2px 8px; border-radius: 6px; font-size: 12px; }
  .badge { padding: 3px 9px; border-radius: 12px; font-size: 11px; font-weight: 600; }
  .badge.ok { background: rgba(39,209,124,0.15); color: #27D17C; }
  .badge.off { background: rgba(255,255,255,0.1); color: rgba(255,255,255,0.6); }
  .badge.err { background: rgba(255,77,77,0.15); color: #FF4D4D; }
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
