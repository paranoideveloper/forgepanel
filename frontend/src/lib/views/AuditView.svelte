<script lang="ts">
	import { tr } from '$lib/i18n';
  import { onMount } from 'svelte';
  import { apiFetch } from '$lib/api';
  import type { AuditLog, AuditPage } from '$lib/types';
  import { showToast } from '$lib/components/Toast.svelte';

  // The panel wrote audit rows from the day the feature landed and nothing ever
  // read them: no store method, no route, no view. An audit log nobody can read
  // is not an audit log — it is a table that grows forever.

  let entries = $state<AuditLog[]>([]);
  let total = $state(0);
  let limit = $state(50);
  let offset = $state(0);
  let loading = $state(true);
  let loadError = $state('');

  let actions = $state<string[]>([]);
  let fActor = $state('');
  let fAction = $state('');
  let fSince = $state('');
  let fUntil = $state('');

  const page = $derived(Math.floor(offset / limit) + 1);
  const pages = $derived(Math.max(1, Math.ceil(total / limit)));

  function query(): string {
    const p = new URLSearchParams();
    if (fActor.trim()) p.set('actor', fActor.trim());
    if (fAction) p.set('action', fAction);
    // <input type="datetime-local"> yields a local wall time with no zone. The
    // API takes RFC3339, so it is converted rather than sent as-is — pasting a
    // zoneless string would be interpreted as UTC and silently shift the window
    // by the operator's offset.
    if (fSince) p.set('since', new Date(fSince).toISOString());
    if (fUntil) p.set('until', new Date(fUntil).toISOString());
    p.set('limit', String(limit));
    p.set('offset', String(offset));
    return p.toString();
  }

  async function load() {
    loading = true;
    loadError = '';
    try {
      const res = await apiFetch<AuditPage>(`/admin/audit?${query()}`);
      entries = res.items ?? [];
      total = res.total ?? 0;
      limit = res.limit || limit;
    } catch (err: any) {
      loadError = err.message || tr('audit.failed_to_load_the_audit_trail');
    } finally {
      loading = false;
    }
  }

  async function loadActions() {
    try {
      const res = await apiFetch<{ actions: string[] }>('/admin/audit/actions');
      actions = res.actions ?? [];
    } catch {
      // A missing filter list is not worth an error banner; the trail still
      // loads and can be filtered by hand.
      actions = [];
    }
  }

  function applyFilters() {
    offset = 0;
    load();
  }

  function clearFilters() {
    fActor = '';
    fAction = '';
    fSince = '';
    fUntil = '';
    offset = 0;
    load();
  }

  function prev() {
    if (offset <= 0) return;
    offset = Math.max(0, offset - limit);
    load();
  }

  function next() {
    if (offset + limit >= total) return;
    offset += limit;
    load();
  }

  function when(iso: string): string {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return d.toLocaleString();
  }

  // Security-relevant events deserve to stand out in a wall of routine changes.
  function severity(action: string): string {
    if (/^(login|2fa\.|sessions\.|admin\.|password)/.test(action)) return 'sec';
    if (/delete|revoke|disable|reset/.test(action)) return 'destructive';
    return '';
  }

  // Which entries have their diff expanded. Collapsed by default: a diff is
  // detail for the one entry being investigated, and showing every one turns
  // the trail into a wall of text.
  let expanded = $state<Record<number, boolean>>({});
  function toggle(id: number) {
    expanded = { ...expanded, [id]: !expanded[id] };
  }

  function copyRow(e: AuditLog) {
    const line = `${e.created_at}\t${e.actor}\t${e.ip}\t${e.action}\t${e.target}`;
    navigator.clipboard
      .writeText(line)
      .then(() => showToast(tr('audit.entry_copied'), 'success'))
      .catch(() => showToast(tr('audit.could_not_copy'), 'error'));
  }

  onMount(() => {
    loadActions();
    load();
  });
</script>

<div class="view-header">
  <h2>{tr('audit.audit_trail')}</h2>
  <button class="btn-primary" onclick={load}>{tr('audit.refresh')}</button>
</div>

<div class="card">
  <div class="filters">
    <label class="fg">
      <span>{tr('audit.actor')}</span>
      <input bind:value={fActor} placeholder={tr('audit.username')} data-testid="filter-actor" />
    </label>
    <label class="fg">
      <span>{tr('audit.action')}</span>
      <select bind:value={fAction} data-testid="filter-action">
        <option value="">{tr('audit.any')}</option>
        {#each actions as a}<option value={a}>{a}</option>{/each}
      </select>
    </label>
    <label class="fg">
      <span>{tr('audit.from')}</span>
      <input type="datetime-local" bind:value={fSince} />
    </label>
    <label class="fg">
      <span>{tr('audit.to')}</span>
      <input type="datetime-local" bind:value={fUntil} />
    </label>
    <button class="btn-primary" onclick={applyFilters}>{tr('audit.apply')}</button>
    <button class="btn-secondary" onclick={clearFilters}>{tr('audit.clear')}</button>
  </div>
</div>

<div class="card table-card">
  {#if loading}
    <p class="muted">{tr('audit.loading_the_audit_trail')}</p>
  {:else if loadError}
    <p class="err-text">{loadError}</p>
  {:else if entries.length === 0}
    <p class="muted" data-testid="empty">
      {total === 0 && !fActor && !fAction && !fSince && !fUntil
        ? tr('audit.nothing_recorded_yet')
        : tr('audit.no_entries_match_these_filters')}
    </p>
  {:else}
    <table>
      <thead>
        <tr>
          <th>{tr('audit.when')}</th>
          <th>{tr('audit.actor')}</th>
          <th>IP</th>
          <th>{tr('audit.action')}</th>
          <th>{tr('audit.target')}</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each entries as e}
          <tr class={severity(e.action)}>
            <td class="mono">{when(e.created_at)}</td>
            <td><strong>{e.actor || '—'}</strong></td>
            <td class="mono">{e.ip || '—'}</td>
            <td><span class="badge">{e.action}</span></td>
            <td class="target" title={e.target}>{e.target || '—'}</td>
            <td class="row-actions">
              {#if e.diff}
                <button class="btn-sm" onclick={() => toggle(e.id)} data-testid="toggle-diff">
                  {expanded[e.id] ? tr('audit.hide') : tr('audit.what_changed')}
                </button>
              {/if}
              <button class="btn-sm" onclick={() => copyRow(e)}>{tr('audit.copy')}</button>
            </td>
          </tr>
          {#if e.diff && expanded[e.id]}
            <tr class="diff-row">
              <!-- Credentials are recorded as "changed" without their values, so
                   this is safe to render in full. -->
              <td colspan="6"><pre data-testid="diff">{e.diff.split('; ').join('\n')}</pre></td>
            </tr>
          {/if}
        {/each}
      </tbody>
    </table>

    <div class="pager">
      <button class="btn-secondary" onclick={prev} disabled={offset <= 0}>{tr('audit.previous')}</button>
      <!-- The total is what makes a page meaningful: "50 shown" says nothing
           about whether that is the whole story. -->
      <span class="muted" data-testid="pager">
        {tr('audit.page_of', { page, pages, total, p4: total === 1 ? 'entry' : 'entries' })}
      </span>
      <button class="btn-secondary" onclick={next} disabled={offset + limit >= total}>{tr('audit.next')}</button>
    </div>
  {/if}
</div>

<style>
  .view-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
  .view-header h2 { margin: 0; font-size: 20px; font-weight: 650; }
  .card { background: var(--card); border: 1px solid var(--ln-3); border-radius: 14px; padding: 20px; margin-bottom: 20px; }
  .filters { display: flex; flex-wrap: wrap; gap: 12px; align-items: flex-end; }
  .fg { display: flex; flex-direction: column; gap: 4px; font-size: 12px; color: var(--t-3); }
  input, select { background: var(--bg); border: 1px solid var(--ln-5); color: var(--fg); padding: 9px; border-radius: 8px; font: inherit; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: start; padding: 9px 12px; border-bottom: 1px solid var(--ln-2); font-size: 13px; }
  th { color: var(--t-6); font-weight: 600; text-transform: uppercase; font-size: 11px; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; color: var(--t-2); }
  .target { max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  /* Security-relevant events stand out from routine changes; the left border
     carries the signal so it is not colour alone. */
  tr.sec td:first-child { border-inline-start: 3px solid var(--warn); }
  tr.destructive td:first-child { border-inline-start: 3px solid var(--bad-2); }
  .badge { padding: 3px 8px; border-radius: 999px; font-size: 11px; background: var(--ln-3); }
  .muted { color: var(--t-6); font-size: 13px; }
  .err-text { color: var(--bad-2); font-size: 13px; }
  .pager { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-top: 14px; }
  .btn-primary, .btn-secondary, .btn-sm { border-radius: 8px; border: 1px solid transparent; cursor: pointer; font: inherit; }
  .btn-primary { background: var(--acc); color: var(--card-deep); padding: 9px 16px; font-weight: 600; }
  .btn-secondary { background: var(--ln-3); color: var(--fg); padding: 9px 16px; }
  .btn-secondary:disabled { opacity: 0.4; cursor: default; }
  .btn-sm { background: var(--ln-3); color: var(--fg); padding: 4px 10px; font-size: 12px; }
  .row-actions { display: flex; gap: 6px; }
  .diff-row td { padding-top: 0; }
  .diff-row pre {
    margin: 0 0 8px;
    padding: 10px 12px;
    background: var(--bg);
    border: 1px solid var(--ln-3);
    border-radius: 6px;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 12px;
    line-height: 1.6;
    white-space: pre-wrap;
    color: var(--t-2);
  }
</style>
