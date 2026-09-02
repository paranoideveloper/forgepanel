<script lang="ts">
  import { tr } from '$lib/i18n';
  import { onMount, onDestroy } from 'svelte';
  import { apiFetch } from '$lib/api';
  import { showToast } from '$lib/components/Toast.svelte';

  // The engines subsystem had no UI at all. /api/admin/engines has always
  // reported live supervised state — pid, restarts, responsiveness, recent log
  // lines, and for the kernel cores which interfaces are up — and the only way
  // to read any of it was curl. So the question an operator actually asks when
  // an inbound is not working ("is the core that serves it even running?") could
  // not be answered from the panel.
  interface Engine {
    engine: string;
    state: string;
    pid?: number;
    restarts?: number;
    responsive?: boolean;
    last_error?: string;
    recent_logs?: string[];
    details?: {
      interfaces?: Array<{ engine?: string; interface?: string; up?: boolean }>;
      kernel?: { tools_installed?: boolean; module_loaded?: boolean; kernel_ready?: boolean; last_error?: string };
    };
  }

  let engines = $state<Engine[]>([]);
  let loading = $state(true);
  let openLogs = $state<Record<string, boolean>>({});
  let timer: ReturnType<typeof setInterval> | undefined;

  async function load(showErrors = true) {
    try {
      engines = (await apiFetch<Engine[]>('/admin/engines')) ?? [];
    } catch (err: any) {
      if (showErrors) showToast(err?.message ?? String(err), 'error');
    } finally {
      loading = false;
    }
  }

  async function reload() {
    try {
      await apiFetch('/admin/engines/reload', { method: 'POST' });
      showToast(tr('engines.reloaded'), 'success');
      await load();
    } catch (err: any) {
      showToast(err?.message ?? String(err), 'error');
    }
  }

  onMount(() => {
    load();
    timer = setInterval(() => load(false), 5000);
  });
  onDestroy(() => clearInterval(timer));

  // "unavailable" is not a failure and must not be painted as one: it means the
  // host never had the capability (no kernel module, no tools), so the operator
  // needs to install a package, not read a crash log.
  function tone(state: string): string {
    if (state === 'running') return 'ok';
    if (state === 'unavailable') return 'muted';
    if (state === 'stopped') return 'warn';
    return 'bad';
  }
</script>

<div class="engines">
  <header>
    <h2>{tr('engines.title')}</h2>
    <button class="btn" onclick={reload}>{tr('engines.reload')}</button>
  </header>

  {#if loading}
    <p class="muted">{tr('engines.loading')}</p>
  {:else if engines.length === 0}
    <p class="muted">{tr('engines.none')}</p>
  {:else}
    <div class="grid">
      {#each engines as e (e.engine)}
        <section class="card">
          <div class="head">
            <h3>{e.engine}</h3>
            <span class="badge {tone(e.state)}">{e.state}</span>
          </div>

          <dl>
            {#if e.pid}
              <div><dt>{tr('engines.pid')}</dt><dd>{e.pid}</dd></div>
            {/if}
            {#if e.restarts !== undefined}
              <div><dt>{tr('engines.restarts')}</dt><dd>{e.restarts}</dd></div>
            {/if}
            {#if e.responsive !== undefined}
              <div>
                <dt>{tr('engines.responsive')}</dt>
                <dd>{e.responsive ? tr('engines.yes') : tr('engines.no')}</dd>
              </div>
            {/if}
          </dl>

          {#if e.details?.kernel}
            <dl class="kernel">
              <div>
                <dt>{tr('engines.tools')}</dt>
                <dd>{e.details.kernel.tools_installed ? tr('engines.yes') : tr('engines.no')}</dd>
              </div>
              <div>
                <dt>{tr('engines.module')}</dt>
                <dd>{e.details.kernel.module_loaded ? tr('engines.yes') : tr('engines.no')}</dd>
              </div>
            </dl>
          {/if}

          {#if e.details?.interfaces?.length}
            <ul class="ifaces">
              {#each e.details.interfaces as i}
                <li>
                  <span class="dot {i.up ? 'ok' : 'bad'}"></span>{i.interface}
                </li>
              {/each}
            </ul>
          {/if}

          {#if e.last_error}
            <p class="err">{e.last_error}</p>
          {/if}

          {#if e.recent_logs?.length}
            <button
              class="link"
              onclick={() => (openLogs = { ...openLogs, [e.engine]: !openLogs[e.engine] })}
            >
              {openLogs[e.engine] ? tr('engines.hide_logs') : tr('engines.show_logs')}
            </button>
            {#if openLogs[e.engine]}
              <pre>{e.recent_logs.join('\n')}</pre>
            {/if}
          {/if}
        </section>
      {/each}
    </div>
  {/if}
</div>

<style>
  .engines { padding: 4px 0; }
  header { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
  h2 { margin: 0 0 12px; font-size: 18px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 14px; }
  .card {
    background: var(--panel, #141a24);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 12px;
    padding: 14px 16px;
  }
  .head { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
  h3 { margin: 0 0 8px; font-size: 15px; font-family: ui-monospace, monospace; }
  .badge { font-size: 11px; font-weight: 700; padding: 3px 8px; border-radius: 999px; text-transform: uppercase; }
  .badge.ok { background: rgba(34, 197, 94, 0.16); color: #4ade80; }
  .badge.warn { background: rgba(234, 179, 8, 0.16); color: #facc15; }
  .badge.bad { background: rgba(239, 68, 68, 0.16); color: #f87171; }
  .badge.muted { background: rgba(255, 255, 255, 0.08); color: rgba(255, 255, 255, 0.55); }
  dl { display: flex; flex-wrap: wrap; gap: 6px 18px; margin: 10px 0 0; }
  dl div { display: flex; gap: 6px; font-size: 13px; }
  dt { color: rgba(255, 255, 255, 0.5); }
  dd { margin: 0; font-variant-numeric: tabular-nums; }
  .ifaces { list-style: none; margin: 10px 0 0; padding: 0; font-size: 13px; font-family: ui-monospace, monospace; }
  .ifaces li { display: flex; align-items: center; gap: 7px; }
  .dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
  .dot.ok { background: #4ade80; }
  .dot.bad { background: #f87171; }
  .err { margin: 10px 0 0; font-size: 12px; color: #f87171; word-break: break-word; }
  .muted { color: rgba(255, 255, 255, 0.55); }
  pre {
    margin: 8px 0 0; padding: 10px; border-radius: 8px; background: rgba(0, 0, 0, 0.35);
    font-size: 11px; line-height: 1.45; max-height: 240px; overflow: auto; white-space: pre-wrap;
    word-break: break-word;
  }
  .link { background: none; border: 0; color: #7dd3fc; cursor: pointer; font: inherit; font-size: 12px; padding: 8px 0 0; }
  .btn {
    background: #1a2230; color: #fff; border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 9px; padding: 8px 12px; font: inherit; font-size: 13px; font-weight: 700; cursor: pointer;
  }
</style>
