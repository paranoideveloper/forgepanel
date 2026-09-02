<script lang="ts">
  import { tr } from '$lib/i18n';
  import { onMount } from 'svelte';
  import { apiFetch } from '$lib/api';
  import { showToast } from '$lib/components/Toast.svelte';

  // Outbound webhook endpoints.
  //
  // The dispatcher, the HMAC signature and the retry queue all shipped without
  // anywhere to point them: creating an endpoint meant writing the REST call by
  // hand, and an operator who cannot list them cannot see that one has been
  // answering 401 since Tuesday either — which from every other screen in the
  // panel is indistinguishable from nothing having happened.

  interface Endpoint {
    id: number;
    url: string;
    events: string;
    enabled: boolean;
    proxy_url: string;
    has_secret: boolean;
    last_status: number;
    last_error: string;
    last_attempt?: string;
  }

  let rows = $state<Endpoint[]>([]);
  // The event names are read from the server on every load and never written
  // down here. The set is closed on the backend for a reason: an endpoint
  // subscribed to "node_down" instead of "node-down" is enabled, green, and
  // permanently silent, and nothing in a working panel would ever reveal it.
  // A copy of the list in this file is a second place for that typo to live.
  let eventTypes = $state<string[]>([]);
  let busy = $state(false);
  let err = $state('');
  let remedy = $state('');

  let newURL = $state('');
  let newProxy = $state('');
  let chosen = $state<Record<string, boolean>>({});

  // The secret is minted by the panel and returned exactly once. No later read
  // carries it, so this is the only moment it can be handed over; losing it
  // means the receiver can never verify a signature again without rotating.
  let revealed = $state('');

  function whenText(iso: string): string {
    const d = new Date(iso);
    return isNaN(d.getTime()) ? iso : d.toLocaleString();
  }

  async function load() {
    // Any read invalidates the reveal: the list response carries has_secret and
    // nothing else, so leaving it on screen would imply the panel still holds
    // something it does not.
    revealed = '';
    try {
      const res = await apiFetch<{ webhooks: Endpoint[]; events: string[] }>('/admin/settings/webhooks');
      rows = res.webhooks ?? [];
      eventTypes = res.events ?? [];
    } catch (e: any) {
      err = e.message || tr('systemhealth.webhook_load_failed');
    }
  }

  function selectedEvents(): string {
    // Empty means "everything", which is what the backend's normalizeEvents
    // treats an empty string as. Sending the full list instead would silently
    // stop delivering any event added to the panel later.
    return eventTypes.filter((e) => chosen[e]).join(',');
  }

  async function create() {
    busy = true;
    err = '';
    remedy = '';
    try {
      const res = await apiFetch<Endpoint & { secret?: string }>('/admin/settings/webhooks', {
        method: 'POST',
        body: JSON.stringify({ url: newURL.trim(), events: selectedEvents(), proxy_url: newProxy.trim() })
      });
      newURL = '';
      newProxy = '';
      chosen = {};
      await load();
      // After load(), which clears it — the reveal is the one thing a reload
      // must not be able to reconstruct.
      if (res.secret) revealed = res.secret;
      showToast(tr('systemhealth.webhook_saved'), 'success');
    } catch (e: any) {
      err = e.message || tr('systemhealth.webhook_failed');
      remedy = e.remediation ?? '';
    } finally {
      busy = false;
    }
  }

  async function toggle(row: Endpoint) {
    busy = true;
    err = '';
    try {
      await apiFetch(`/admin/settings/webhooks/${row.id}`, {
        method: 'PUT',
        body: JSON.stringify({ enabled: !row.enabled })
      });
      await load();
    } catch (e: any) {
      err = e.message || tr('systemhealth.webhook_failed');
    } finally {
      busy = false;
    }
  }

  async function test(row: Endpoint) {
    busy = true;
    err = '';
    remedy = '';
    try {
      await apiFetch(`/admin/settings/webhooks/${row.id}/test`, { method: 'POST' });
      showToast(tr('systemhealth.webhook_test_delivered'), 'success');
      await load();
    } catch (e: any) {
      // The receiver's own status, not the gateway 502 the panel wrapped it in.
      // "Delivery failed" sends an operator to read logs; "401" sends them to
      // the receiver's auth config, which is where the problem is.
      const status = (e.body?.status as number) || e.status;
      err = `${status} — ${e.message}`;
      remedy = e.remediation ?? '';
    } finally {
      busy = false;
    }
  }

  async function remove(row: Endpoint) {
    busy = true;
    err = '';
    try {
      await apiFetch(`/admin/settings/webhooks/${row.id}`, { method: 'DELETE' });
      await load();
      showToast(tr('systemhealth.webhook_deleted'), 'success');
    } catch (e: any) {
      err = e.message || tr('systemhealth.webhook_failed');
    } finally {
      busy = false;
    }
  }

  onMount(load);
</script>

<div class="card" data-testid="webhooks-card">
  <h3>{tr('systemhealth.webhooks_title')}</h3>
  <p class="hint">{tr('systemhealth.webhooks_hint')}</p>

  {#if rows.length === 0}
    <p class="hint" data-testid="webhooks-empty">{tr('systemhealth.webhook_none')}</p>
  {:else}
    <ul class="wh-list">
      {#each rows as row (row.id)}
        <li class="wh-row" data-testid={`webhook-row-${row.id}`}>
          <div class="wh-main">
            <code>{row.url}</code>
            <span class="wh-events">{row.events || tr('systemhealth.webhook_events_all')}</span>
          </div>
          <div class="wh-status">
            {#if row.last_attempt}
              <span data-testid={`webhook-last-${row.id}`}>
                {tr('systemhealth.webhook_last_attempt', { status: row.last_status, when: whenText(row.last_attempt) })}
                {row.last_error}
              </span>
            {:else}
              <span>{tr('systemhealth.webhook_never_delivered')}</span>
            {/if}
          </div>
          <div class="wh-actions">
            <button class="btn-secondary" data-testid={`webhook-enabled-${row.id}`}
                    disabled={busy} onclick={() => toggle(row)}>
              {row.enabled ? tr('systemhealth.webhook_disable') : tr('systemhealth.webhook_enable')}
            </button>
            <button class="btn-secondary" data-testid={`webhook-test-${row.id}`}
                    disabled={busy} onclick={() => test(row)}>{tr('systemhealth.webhook_test')}</button>
            <button class="btn-danger" data-testid={`webhook-delete-${row.id}`}
                    disabled={busy} onclick={() => remove(row)}>{tr('systemhealth.webhook_delete')}</button>
          </div>
        </li>
      {/each}
    </ul>
  {/if}

  {#if revealed}
    <div class="wh-secret" data-testid="webhook-secret-reveal">
      <p class="hint">{tr('systemhealth.webhook_secret_once')}</p>
      <code>{revealed}</code>
    </div>
  {/if}

  <div class="form-grid">
    <input bind:value={newURL} data-testid="webhook-url" placeholder={tr('systemhealth.webhook_url_placeholder')} />
    <input bind:value={newProxy} data-testid="webhook-proxy" placeholder={tr('systemhealth.webhook_proxy_placeholder')} />
  </div>

  <p class="hint">{tr('systemhealth.webhook_events_choose')}</p>
  <div class="wh-events-grid">
    {#each eventTypes as ev (ev)}
      <label class="chk">
        <input type="checkbox" data-testid={`webhook-event-${ev}`} bind:checked={chosen[ev]} />
        <span>{ev}</span>
      </label>
    {/each}
  </div>

  <div class="wh-actions">
    <button class="btn-primary" data-testid="webhook-create" disabled={busy} onclick={create}>
      {busy ? tr('systemhealth.webhook_working') : tr('systemhealth.webhook_add')}
    </button>
    <button class="btn-secondary" data-testid="webhook-refresh" disabled={busy} onclick={load}>
      {tr('systemhealth.refresh')}
    </button>
  </div>

  {#if err}
    <p class="err-text" data-testid="webhook-error">{err}</p>
    {#if remedy}<p class="hint" data-testid="webhook-remedy">{remedy}</p>{/if}
  {/if}
</div>

<style>
  .wh-list { list-style: none; margin: 0 0 12px; padding: 0; }
  .wh-row {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    align-items: center;
    justify-content: space-between;
    padding: 10px 0;
    border-block-end: 1px solid var(--border);
  }
  .wh-main { display: flex; flex-direction: column; gap: 2px; min-inline-size: 0; }
  .wh-main code { overflow-wrap: anywhere; }
  .wh-events { font-size: 12px; opacity: 0.7; }
  .wh-status { font-size: 12px; opacity: 0.8; }
  .wh-actions { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
  .wh-events-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
    gap: 4px 12px;
    margin-block-end: 12px;
  }
  .wh-secret {
    margin-block-end: 12px;
    padding: 10px 12px;
    border: 1px solid var(--accent);
    border-radius: 6px;
  }
  .wh-secret code { display: block; margin-block: 6px; overflow-wrap: anywhere; }
</style>
