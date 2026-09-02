<script lang="ts">
	import { tr } from '$lib/i18n';
  import { onMount, onDestroy } from 'svelte';
  import { apiFetch } from '$lib/api';
  import { DEFAULT_PRESENCE_TTL_SECONDS, setPresenceTtlSeconds } from '$lib/presence';

  // Who is connected, right now.
  //
  // The panel could say how many bytes a user had ever moved and nothing about
  // whether they were connected at this moment, from where, or on which inbound.
  // That is the first thing anyone wants when a customer says "it's not
  // working", and the only way to spot one account shared across a dozen
  // households.

  interface Session {
    ip: string;
    inbound: string;
    node: string;
    first_seen: string;
    last_seen: string;
    connections: number;
  }
  interface OnlineUser {
    user_id: number;
    username: string;
    last_seen: string;
    addresses: number;
    sessions: Session[];
  }

  let users = $state<OnlineUser[]>([]);
  let ttl = $state(DEFAULT_PRESENCE_TTL_SECONDS);
  let loading = $state(true);
  let loadError = $state('');
  let expanded = $state<Record<string, boolean>>({});
  let timer: ReturnType<typeof setInterval> | undefined;

  // Presence is only interesting while it is current, so this refreshes on its
  // own. Ten seconds is fast enough that a reconnect shows up while the operator
  // is still looking, and slow enough not to hammer the panel.
  const REFRESH_MS = 10_000;

  async function load(showSpinner = false) {
    if (showSpinner) loading = true;
    try {
      const res = await apiFetch<{ users: OnlineUser[]; ttl_seconds: number }>('/admin/online');
      users = res.users ?? [];
      // The server publishes its window so readers do not have to guess it.
      // Handing it to the shared presence module rather than keeping it local
      // is the point: the Users table's presence dot answers the same question
      // and must not answer it with a different number.
      ttl = setPresenceTtlSeconds(res.ttl_seconds);
      loadError = '';
    } catch (err: any) {
      // A failed poll must not blank the list: the last good picture is more
      // useful than an empty screen that reads as "nobody is connected".
      loadError = err.message || tr('online.failed_to_load_presence');
    } finally {
      loading = false;
    }
  }

  function ago(iso: string): string {
    const t = new Date(iso).getTime();
    if (Number.isNaN(t)) return '—';
    const s = Math.max(0, Math.round((Date.now() - t) / 1000));
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    return `${Math.floor(s / 3600)}h ago`;
  }

  function since(iso: string): string {
    const t = new Date(iso).getTime();
    if (Number.isNaN(t)) return '—';
    const s = Math.max(0, Math.round((Date.now() - t) / 1000));
    if (s < 60) return `${s}s`;
    if (s < 3600) return `${Math.floor(s / 60)}m`;
    return `${Math.floor(s / 3600)}h`;
  }

  function toggle(key: string) {
    expanded = { ...expanded, [key]: !expanded[key] };
  }

  const totalSessions = $derived(users.reduce((n, u) => n + u.sessions.length, 0));

  onMount(() => {
    load(true);
    timer = setInterval(() => load(false), REFRESH_MS);
  });
  // Without this the poll outlives the view and keeps requesting forever.
  onDestroy(() => {
    if (timer !== undefined) clearInterval(timer);
  });
</script>

<div class="view-header">
  <h2>{tr('online.online')}</h2>
  <div class="hdr-right">
    <span class="muted" data-testid="summary">
      {users.length} {users.length === 1 ? 'user' : 'users'} · {totalSessions}
      {totalSessions === 1 ? 'address' : 'addresses'}
    </span>
    <button class="btn-primary" onclick={() => load(true)}>{tr('online.refresh')}</button>
  </div>
</div>

{#if loadError}
  <div class="card"><p class="err-text">{loadError}</p></div>
{/if}

<div class="card">
  {#if loading}
    <p class="muted">{tr('online.loading')}</p>
  {:else if users.length === 0}
    <p class="muted" data-testid="empty">
      {tr('online.nobody_is_connected_a_user_counts', { ttl })}
    </p>
  {:else}
    <table>
      <thead>
        <tr>
          <th>{tr('online.user')}</th>
          <th>{tr('online.addresses')}</th>
          <th>{tr('online.last_seen')}</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each users as u (u.username)}
          <tr>
            <td>
              <span class="dot"></span>
              <strong>{u.username}</strong>
            </td>
            <!-- The address count is what an operator scans for: one account on
                 eight addresses is a shared account. -->
            <td>
              <span class="count" class:many={u.addresses > 3}>{u.addresses}</span>
            </td>
            <td class="mono">{ago(u.last_seen)}</td>
            <td>
              <button class="btn-sm" data-testid="toggle" onclick={() => toggle(u.username)}>
                {expanded[u.username] ? tr('online.hide') : tr('online.where_from')}
              </button>
            </td>
          </tr>
          {#if expanded[u.username]}
            <tr class="detail">
              <td colspan="4">
                <table class="inner">
                  <thead>
                    <tr><th>{tr('online.address')}</th><th>{tr('online.inbound')}</th><th>{tr('online.node')}</th><th>{tr('online.connected')}</th><th>{tr('online.conns')}</th></tr>
                  </thead>
                  <tbody>
                    {#each u.sessions as sess}
                      <tr>
                        <td class="mono">{sess.ip}</td>
                        <td>{sess.inbound || '—'}</td>
                        <td>{sess.node || '—'}</td>
                        <td class="mono">{since(sess.first_seen)}</td>
                        <td class="mono">{sess.connections}</td>
                      </tr>
                    {/each}
                  </tbody>
                </table>
              </td>
            </tr>
          {/if}
        {/each}
      </tbody>
    </table>
    <p class="foot muted">
      {tr('online.presence_is_inferred_from_the_last', { ttl })}
    </p>
  {/if}
</div>

<style>
  .view-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; gap: 12px; flex-wrap: wrap; }
  .view-header h2 { margin: 0; font-size: 20px; font-weight: 650; }
  .hdr-right { display: flex; align-items: center; gap: 12px; }
  .card { background: var(--card); border: 1px solid var(--ln-3); border-radius: 14px; padding: 20px; margin-bottom: 20px; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: start; padding: 9px 12px; border-bottom: 1px solid var(--ln-2); font-size: 13px; }
  th { color: var(--t-6); font-weight: 600; text-transform: uppercase; font-size: 11px; }
  .dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: var(--ok-2); margin-inline-end: 8px; }
  .count { display: inline-block; min-width: 24px; text-align: center; padding: 2px 8px; border-radius: 999px; background: var(--ln-3); font-size: 12px; }
  /* Many simultaneous addresses is the signal worth noticing, so it is marked
     by weight and border as well as colour. */
  .count.many { background: rgba(217,155,43,0.18); color: var(--warn); font-weight: 700; border: 1px solid rgba(217,155,43,0.4); }
  .detail td { background: var(--ln-1); padding-top: 0; }
  .inner th, .inner td { font-size: 12px; padding: 6px 10px; border-bottom: 1px solid var(--ln-1); }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; color: var(--t-2); }
  .muted { color: var(--t-6); font-size: 13px; }
  .foot { margin: 14px 0 0; font-size: 12px; }
  .err-text { color: var(--bad-2); font-size: 13px; }
  .btn-primary { background: var(--acc); color: var(--card-deep); padding: 9px 16px; font-weight: 600; border: 0; border-radius: 8px; cursor: pointer; font: inherit; }
  .btn-sm { background: var(--ln-3); color: var(--fg); padding: 4px 10px; font-size: 12px; border: 0; border-radius: 8px; cursor: pointer; font: inherit; }
</style>
