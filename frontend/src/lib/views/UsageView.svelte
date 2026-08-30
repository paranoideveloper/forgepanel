<script lang="ts">
	import { tr } from '$lib/i18n';
  import { onMount } from 'svelte';
  import { apiFetch } from '$lib/api';
  import TrafficChart from '$lib/components/TrafficChart.svelte';
  import { showToast } from '$lib/components/Toast.svelte';

  // Usage over time. The panel knew totals and nothing about when, so there was
  // no answer to "why did this spike on Tuesday" and no report for a customer
  // disputing a bill.

  interface Point {
    bucket: string;
    bytes: number;
  }
  interface TopRow {
    key: string;
    bytes: number;
  }
  interface UserRow {
    id: number;
    username: string;
  }

  let period = $state<'hour' | 'day'>('hour');
  let scope = $state<'user' | 'node'>('user');
  let selectedKey = $state('');
  let points = $state<Point[]>([]);
  let top = $state<TopRow[]>([]);
  let users = $state<UserRow[]>([]);
  let loading = $state(true);
  let loadError = $state('');

  // Names, so the chart says "alice" rather than "17". A key with no name is
  // shown as the key — better than hiding a real consumer because its user row
  // was deleted.
  const nameFor = $derived((key: string) => users.find((u) => String(u.id) === key)?.username || key);

  const windowFor = $derived(() => {
    const hours = period === 'day' ? 24 * 30 : 48;
    return new Date(Date.now() - hours * 3600_000).toISOString();
  });

  async function loadTop() {
    const q = new URLSearchParams({ scope, period, since: windowFor(), limit: '10' });
    const res = await apiFetch<{ items: TopRow[] }>(`/admin/traffic/top?${q}`);
    top = res.items ?? [];
    // Default to the heaviest consumer: it is the one being looked for.
    if (!selectedKey && top.length) selectedKey = top[0].key;
  }

  async function loadSeries() {
    if (!selectedKey) {
      points = [];
      return;
    }
    const q = new URLSearchParams({ scope, key: selectedKey, period, since: windowFor() });
    const res = await apiFetch<{ points: Point[] }>(`/admin/traffic/series?${q}`);
    points = res.points ?? [];
  }

  async function load() {
    loading = true;
    loadError = '';
    try {
      // Names are a nicety; a failure to fetch them must not stop the charts.
      try {
        users = await apiFetch<UserRow[]>('/admin/users');
      } catch {
        users = [];
      }
      await loadTop();
      await loadSeries();
    } catch (err: any) {
      loadError = err.message || tr('usage.failed_to_load_usage_history');
    } finally {
      loading = false;
    }
  }

  async function pick(key: string) {
    selectedKey = key;
    try {
      await loadSeries();
    } catch (err: any) {
      showToast(err.message || tr('usage.failed_to_load_that_series'), 'error');
    }
  }

  async function changeScope(next: 'user' | 'node') {
    scope = next;
    selectedKey = '';
    await load();
  }

  async function changePeriod(next: 'hour' | 'day') {
    period = next;
    await load();
  }

  function fmt(n: number): string {
    if (!n) return '0';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let v = n;
    let i = 0;
    while (v >= 1024 && i < units.length - 1) {
      v /= 1024;
      i++;
    }
    return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
  }

  onMount(load);
</script>

<div class="view-header">
  <h2>{tr('usage.usage')}</h2>
  <div class="controls">
    <div class="seg">
      <button class:active={scope === 'user'} onclick={() => changeScope('user')} data-testid="scope-user">{tr('usage.users')}</button>
      <button class:active={scope === 'node'} onclick={() => changeScope('node')} data-testid="scope-node">{tr('usage.nodes')}</button>
    </div>
    <div class="seg">
      <button class:active={period === 'hour'} onclick={() => changePeriod('hour')} data-testid="period-hour">{tr('usage.48_hours')}</button>
      <button class:active={period === 'day'} onclick={() => changePeriod('day')} data-testid="period-day">{tr('usage.30_days')}</button>
    </div>
    <button class="btn-primary" onclick={load}>{tr('usage.refresh')}</button>
  </div>
</div>

{#if loadError}
  <div class="card"><p class="err-text">{loadError}</p></div>
{:else if loading}
  <div class="card"><p class="muted">{tr('usage.loading_usage_history')}</p></div>
{:else}
  <div class="card">
    <TrafficChart
      {points}
      {period}
      label={selectedKey ? `${scope === 'user' ? tr('usage.user') : tr('usage.node')} ${nameFor(selectedKey)}` : 'Traffic'}
    />
  </div>

  <div class="card table-card">
    <h3>{tr('usage.top_consumers')}</h3>
    {#if top.length === 0}
      <p class="muted" data-testid="top-empty">
        {tr('usage.no_usage_recorded_yet_history_starts')}
      </p>
    {:else}
      <table>
        <thead>
          <tr><th>{scope === 'user' ? tr('usage.user') : tr('usage.node')}</th><th>{tr('usage.used')}</th><th></th></tr>
        </thead>
        <tbody>
          {#each top as row}
            <tr class:selected={row.key === selectedKey}>
              <td><strong>{nameFor(row.key)}</strong></td>
              <td class="mono">{fmt(row.bytes)}</td>
              <td>
                <button class="btn-sm" onclick={() => pick(row.key)} data-testid="pick">{tr('usage.chart')}</button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </div>
{/if}

<style>
  .view-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; gap: 12px; flex-wrap: wrap; }
  .view-header h2 { margin: 0; font-size: 20px; font-weight: 650; }
  .controls { display: flex; gap: 10px; align-items: center; }
  .seg { display: flex; border: 1px solid var(--ln-5); border-radius: 8px; overflow: hidden; }
  .seg button { background: transparent; color: var(--t-3); border: 0; padding: 8px 12px; font: inherit; cursor: pointer; }
  .seg button.active { background: rgba(255,122,26,0.18); color: var(--acc); }
  .card { background: var(--card); border: 1px solid var(--ln-3); border-radius: 14px; padding: 20px; margin-bottom: 20px; }
  .card h3 { margin: 0 0 14px; font-size: 13px; text-transform: uppercase; color: var(--t-3); }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: start; padding: 9px 12px; border-bottom: 1px solid var(--ln-2); font-size: 13px; }
  th { color: var(--t-6); font-weight: 600; text-transform: uppercase; font-size: 11px; }
  tr.selected td { background: rgba(255,122,26,0.08); }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .muted { color: var(--t-6); font-size: 13px; }
  .err-text { color: var(--bad-2); font-size: 13px; }
  .btn-primary { background: var(--acc); color: var(--card-deep); padding: 9px 16px; font-weight: 600; border: 0; border-radius: 8px; cursor: pointer; font: inherit; }
  .btn-sm { background: var(--ln-3); color: var(--fg); padding: 4px 10px; font-size: 12px; border: 0; border-radius: 8px; cursor: pointer; font: inherit; }
</style>
