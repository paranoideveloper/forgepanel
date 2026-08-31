<script lang="ts">
  import { tr } from '$lib/i18n';
  import { onMount, onDestroy } from 'svelte';
  import { apiFetch } from '$lib/api';
  import { showToast } from '$lib/components/Toast.svelte';

  // The Overview used to show five things: liveness, a version, node counts and
  // the panel's own uptime. An administrator checking whether the SERVER was
  // healthy had to leave the panel and open a shell.
  //
  // Everything below is read from /proc and the database — no estimates, and no
  // synthetic "health score", which looks authoritative and means nothing.
  interface Dash {
    status: string;
    version: string;
    panel: { uptime_seconds: number; public_address?: string };
    system: {
      cpu: { cores: number; load1: number; load5: number; load15: number; percent: number };
      memory: { total: number; used: number; available: number; swap_total: number; swap_used: number };
      disk: { path: string; total: number; used: number; free: number };
      network: { rx_bytes: number; tx_bytes: number };
      host: { hostname: string; os: string; kernel: string; arch: string; uptime_seconds: number };
    };
    traffic: { rx_bytes: number; tx_bytes: number; rx_bytes_per_s: number; tx_bytes_per_s: number };
    accounts: {
      users: number; active: number; disabled: number; expired: number; online: number;
      admins: number; owners: number; resellers: number; viewers: number;
    };
    inbounds: {
      total: number; enabled: number; disabled: number; not_serving: number;
      by_protocol: Record<string, number>;
    };
    nodes: { online: number; total: number };
    warnings?: string[];
  }

  let d = $state<Dash | null>(null);

  // A panel mid-upgrade can still be serving the OLD /overview shape, and a
  // dashboard that throws on a missing field shows nothing at all rather than
  // the half it does have. Every read below goes through these.
  const sys = $derived(d?.system);
  const panel = $derived(d?.panel);
  let loading = $state(true);
  let timer: ReturnType<typeof setInterval> | undefined;

  async function load(showErrors = true) {
    try {
      d = await apiFetch<Dash>('/admin/dashboard');
    } catch (err: any) {
      // Only the first load complains. A dashboard that polls must not queue a
      // toast every few seconds while the panel restarts.
      if (showErrors) showToast(err.message || tr('overview.failed_to_load_system_status'), 'error');
    } finally {
      loading = false;
    }
  }

  function bytes(n?: number): string {
    if (!n || n < 0) return '0 B';
    const u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    let i = 0;
    let v = n;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return `${v < 10 && i > 0 ? v.toFixed(1) : Math.round(v)} ${u[i]}`;
  }

  function duration(seconds?: number): string {
    if (!seconds || seconds < 0) return '—';
    const d0 = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    if (d0 > 0) return `${d0}d ${h}h`;
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m`;
  }

  function pct(used?: number, total?: number): number {
    if (!used || !total || total <= 0) return 0;
    return Math.min(100, Math.round((used / total) * 100));
  }

  // A bar's colour is a judgement, so the thresholds are stated once here rather
  // than scattered through the markup.
  function level(p: number): string {
    if (p >= 90) return 'bad';
    if (p >= 75) return 'warn';
    return 'ok';
  }

  const protocols = $derived(
    Object.entries(d?.inbounds?.by_protocol ?? {}).sort((a, b) => b[1] - a[1])
  );

  onMount(() => {
    load();
    // Five seconds: fast enough that the traffic rate means "now", slow enough
    // that the panel is not answering its own dashboard constantly.
    timer = setInterval(() => load(false), 5000);
  });
  onDestroy(() => { if (timer) clearInterval(timer); });
</script>

<div class="view-header">
  <div>
    <h2>{tr('overview.dashboard_overview')}</h2>
    <p class="header-desc">{tr('overview.real_time_control_plane_health_node')}</p>
  </div>
  <button class="btn-primary" onclick={() => load()}>{tr('overview.refresh')}</button>
</div>

{#if loading && !d}
  <div class="skeleton-grid">
    <div class="skeleton-card"></div><div class="skeleton-card"></div>
    <div class="skeleton-card"></div><div class="skeleton-card"></div>
  </div>
{:else if d && sys}
  {#if d.warnings && d.warnings.length > 0}
    <section class="card warn-card">
      <h3>{tr('overview.needs_attention')}</h3>
      <ul>
        {#each d.warnings as w}<li>{w}</li>{/each}
      </ul>
    </section>
  {/if}

  <!-- The machine. -->
  <div class="grid">
    <section class="card gauge">
      <header><span>{tr('overview.cpu_load')}</span><strong>{d.system.cpu.percent.toFixed(0)}%</strong></header>
      <div class="bar"><div class="fill {level(d.system.cpu.percent)}" style="width:{d.system.cpu.percent}%"></div></div>
      <footer>
        {d.system.cpu.load1.toFixed(2)} · {d.system.cpu.load5.toFixed(2)} · {d.system.cpu.load15.toFixed(2)}
        <span class="dim">· {d.system.cpu.cores} {tr('overview.cores')}</span>
      </footer>
    </section>

    <section class="card gauge">
      <header><span>{tr('overview.memory')}</span><strong>{pct(d.system.memory.used, d.system.memory.total)}%</strong></header>
      <div class="bar"><div class="fill {level(pct(d.system.memory.used, d.system.memory.total))}"
        style="width:{pct(d.system.memory.used, d.system.memory.total)}%"></div></div>
      <footer>
        {bytes(d.system.memory.used)} / {bytes(d.system.memory.total)}
        <span class="dim">· {bytes(d.system.memory.available)} {tr('overview.available')}</span>
      </footer>
    </section>

    <section class="card gauge">
      <header><span>{tr('overview.disk')}</span><strong>{pct(d.system.disk.used, d.system.disk.total)}%</strong></header>
      <div class="bar"><div class="fill {level(pct(d.system.disk.used, d.system.disk.total))}"
        style="width:{pct(d.system.disk.used, d.system.disk.total)}%"></div></div>
      <footer>{bytes(d.system.disk.used)} / {bytes(d.system.disk.total)}
        <span class="dim">· {bytes(d.system.disk.free)} {tr('overview.free')}</span></footer>
    </section>

    <section class="card gauge">
      <header><span>{tr('overview.traffic_now')}</span>
        <strong>↓ {bytes(d.traffic.rx_bytes_per_s)}/s</strong></header>
      <footer>
        ↑ {bytes(d.traffic.tx_bytes_per_s)}/s
        <span class="dim">· {tr('overview.since_boot')} ↓ {bytes(d.traffic.rx_bytes)} ↑ {bytes(d.traffic.tx_bytes)}</span>
      </footer>
    </section>
  </div>

  <!-- Who and what the panel is serving. -->
  <div class="grid">
    <section class="card">
      <h3>{tr('overview.users')}</h3>
      <div class="stats">
        <div class="stat"><span class="k">{tr('overview.total')}</span><span class="v">{d.accounts.users}</span></div>
        <div class="stat"><span class="k">{tr('overview.online')}</span><span class="v ok">{d.accounts.online}</span></div>
        <div class="stat"><span class="k">{tr('overview.active')}</span><span class="v">{d.accounts.active}</span></div>
        <div class="stat"><span class="k">{tr('overview.disabled')}</span><span class="v">{d.accounts.disabled}</span></div>
        <div class="stat"><span class="k">{tr('overview.expired')}</span><span class="v">{d.accounts.expired}</span></div>
      </div>
    </section>

    <section class="card">
      <h3>{tr('overview.administrators')}</h3>
      <div class="stats">
        <div class="stat"><span class="k">{tr('overview.owners')}</span><span class="v">{d.accounts.owners}</span></div>
        <div class="stat"><span class="k">{tr('overview.admins')}</span><span class="v">{d.accounts.admins}</span></div>
        <div class="stat"><span class="k">{tr('overview.resellers')}</span><span class="v">{d.accounts.resellers}</span></div>
        <div class="stat"><span class="k">{tr('overview.viewers')}</span><span class="v">{d.accounts.viewers}</span></div>
      </div>
    </section>

    <section class="card">
      <h3>{tr('overview.inbounds')}</h3>
      <div class="stats">
        <div class="stat"><span class="k">{tr('overview.total')}</span><span class="v">{d.inbounds.total}</span></div>
        <div class="stat"><span class="k">{tr('overview.enabled')}</span><span class="v ok">{d.inbounds.enabled}</span></div>
        <div class="stat"><span class="k">{tr('overview.disabled')}</span><span class="v">{d.inbounds.disabled}</span></div>
        <div class="stat"><span class="k">{tr('overview.not_serving')}</span>
          <span class="v {d.inbounds.not_serving > 0 ? 'bad' : ''}">{d.inbounds.not_serving}</span></div>
      </div>
    </section>

    <section class="card">
      <h3>{tr('overview.nodes')}</h3>
      <div class="stats">
        <div class="stat"><span class="k">{tr('overview.online')}</span><span class="v ok">{d.nodes.online}</span></div>
        <div class="stat"><span class="k">{tr('overview.total')}</span><span class="v">{d.nodes.total}</span></div>
      </div>
    </section>
  </div>

  <!-- Protocol distribution: what this panel is actually serving. -->
  {#if protocols.length > 0}
    <section class="card">
      <h3>{tr('overview.protocol_distribution')}</h3>
      <div class="protos">
        {#each protocols as [name, count]}
          <div class="proto">
            <span class="pname">{name}</span>
            <div class="pbar"><div class="pfill" style="width:{pct(count, d.inbounds.total)}%"></div></div>
            <span class="pcount">{count}</span>
          </div>
        {/each}
      </div>
    </section>
  {/if}

  <!-- The box itself. -->
  <section class="card">
    <h3>{tr('overview.server')}</h3>
    <dl class="facts">
      <dt>{tr('overview.hostname')}</dt><dd>{d.system.host.hostname || '—'}</dd>
      <dt>{tr('overview.operating_system')}</dt><dd>{d.system.host.os || '—'}</dd>
      <dt>{tr('overview.kernel')}</dt><dd>{d.system.host.kernel || '—'} ({d.system.host.arch})</dd>
      <dt>{tr('overview.server_uptime')}</dt><dd>{duration(d.system.host.uptime_seconds)}</dd>
      <dt>{tr('overview.panel_uptime')}</dt><dd>{duration(panel?.uptime_seconds)}</dd>
      <dt>{tr('overview.panel_version')}</dt><dd>{d.version}</dd>
      {#if panel?.public_address}
        <dt>{tr('overview.public_address')}</dt><dd>{panel?.public_address}</dd>
      {/if}
      {#if d.system.memory.swap_total > 0}
        <dt>{tr('overview.swap')}</dt>
        <dd>{bytes(d.system.memory.swap_used)} / {bytes(d.system.memory.swap_total)}</dd>
      {/if}
    </dl>
  </section>
{/if}

<style>
  .view-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
  .view-header h2 { margin: 0; font-size: 20px; font-weight: 650; }
  .header-desc { margin: 4px 0 0; color: var(--t-6); font-size: 13px; }
  .btn-primary { background: var(--acc); color: var(--on-acc); border: none; border-radius: 8px;
    padding: 9px 16px; font: inherit; font-weight: 600; cursor: pointer; }

  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; margin-bottom: 16px; }
  .card { background: var(--card); border: 1px solid var(--ln-3); border-radius: 14px; padding: 16px 18px; }
  .card h3 { margin: 0 0 12px; font-size: 13px; font-weight: 600; color: var(--t-5);
    text-transform: uppercase; letter-spacing: .04em; }

  .warn-card { border-color: var(--warn); margin-bottom: 16px; }
  .warn-card ul { margin: 0; padding-inline-start: 20px; }
  .warn-card li { font-size: 13px; color: var(--t-2); margin: 4px 0; }

  .gauge header { display: flex; justify-content: space-between; align-items: baseline; font-size: 13px; color: var(--t-5); }
  .gauge header strong { font-size: 22px; font-weight: 650; color: var(--fg); }
  .gauge footer { margin-top: 8px; font-size: 12px; color: var(--t-5); }
  .dim { color: var(--t-7); }

  .bar { height: 6px; border-radius: 999px; background: var(--ln-3); margin-top: 10px; overflow: hidden; }
  .fill { height: 100%; border-radius: 999px; transition: width .4s ease; }
  .fill.ok { background: var(--ok); }
  .fill.warn { background: var(--warn); }
  .fill.bad { background: var(--bad); }

  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(72px, 1fr)); gap: 10px; }
  .stat { display: flex; flex-direction: column; gap: 2px; }
  .stat .k { font-size: 11px; color: var(--t-7); text-transform: uppercase; letter-spacing: .03em; }
  .stat .v { font-size: 19px; font-weight: 650; }
  .stat .v.ok { color: var(--ok); }
  .stat .v.bad { color: var(--bad); }

  .protos { display: flex; flex-direction: column; gap: 8px; }
  .proto { display: grid; grid-template-columns: 108px 1fr 40px; align-items: center; gap: 10px; font-size: 13px; }
  .pname { color: var(--t-3); }
  .pbar { height: 6px; background: var(--ln-3); border-radius: 999px; overflow: hidden; }
  .pfill { height: 100%; background: var(--acc); border-radius: 999px; }
  .pcount { text-align: end; color: var(--t-5); }

  .facts { display: grid; grid-template-columns: max-content 1fr; gap: 6px 18px; margin: 0; font-size: 13px; }
  .facts dt { color: var(--t-7); }
  .facts dd { margin: 0; color: var(--t-2); }

  .skeleton-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; }
  .skeleton-card { height: 96px; border-radius: 14px; background: var(--ln-2); animation: pulse 1.4s ease-in-out infinite; }
  @keyframes pulse { 50% { opacity: .5; } }
</style>
