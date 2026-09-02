<script lang="ts">
	import { tr } from '$lib/i18n';
  import { onMount } from 'svelte';
  import { apiFetch } from '$lib/api';
  import { showToast } from '$lib/components/Toast.svelte';

  interface Domain {
    id: number;
    name: string;
    is_default: boolean;
    provider?: string;
    tls_mode?: string;
    note?: string;
  }
  interface DomainFree {
    protocol: string;
    security?: string;
    label: string;
    recommended?: boolean;
    why: string;
  }
  interface DomainStatus {
    has_domain: boolean;
    default_domain: string;
    count: number;
    domain_free: DomainFree[];
    guidance_en: string;
    guidance_fa: string;
  }

  let domains = $state<Domain[]>([]);
  let status = $state<DomainStatus | null>(null);
  let loading = $state(true);
  let newName = $state('');
  let newProvider = $state('');
  let adding = $state(false);

  async function load() {
    loading = true;
    try {
      domains = await apiFetch<Domain[]>('/admin/domains');
      status = await apiFetch<DomainStatus>('/admin/domains-status');
    } catch (err: any) {
      showToast(err.message || tr('domains.failed_to_load_domains'), 'error');
    } finally {
      loading = false;
    }
  }

  async function addDomain() {
    const name = newName.trim();
    if (!name) return;
    adding = true;
    try {
      await apiFetch('/admin/domains', {
        method: 'POST',
        body: JSON.stringify({ name, provider: newProvider.trim() })
      });
      showToast(tr('domains.domain_name_added', { name }), 'success');
      newName = '';
      newProvider = '';
      await load();
    } catch (err: any) {
      showToast(err.message || tr('domains.failed_to_add_domain'), 'error');
    } finally {
      adding = false;
    }
  }

  async function makeDefault(d: Domain) {
    try {
      await apiFetch(`/admin/domains/${d.id}`, {
        method: 'PUT',
        body: JSON.stringify({ is_default: true })
      });
      showToast(tr('domains.name_is_now_the_default_domain', { name: d.name }), 'success');
      await load();
    } catch (err: any) {
      showToast(err.message || tr('domains.failed'), 'error');
    }
  }

  async function removeDomain(d: Domain) {
    if (!confirm(tr('domains.delete_name_inbounds_using_it_will', { name: d.name }))) return;
    try {
      await apiFetch(`/admin/domains/${d.id}`, { method: 'DELETE' });
      showToast(tr('domains.name_deleted', { name: d.name }), 'success');
      await load();
    } catch (err: any) {
      if (err.status === 409) {
        if (confirm(tr('domains.name_is_still_used_by_inbounds', { name: d.name }))) {
          try {
            await apiFetch(`/admin/domains/${d.id}?force=true`, { method: 'DELETE' });
            showToast(tr('domains.name_deleted', { name: d.name }), 'success');
            await load();
          } catch (e: any) {
            showToast(e.message || tr('domains.failed'), 'error');
          }
        }
      } else {
        showToast(err.message || tr('domains.failed'), 'error');
      }
    }
  }

  async function realityQuickstart() {
    try {
      const res = await apiFetch<{ port: number }>('/admin/inbounds/reality-quickstart', {
        method: 'POST',
        body: JSON.stringify({})
      });
      showToast(tr('domains.reality_inbound_created_on_port_port', { port: res.port }), 'success');
    } catch (err: any) {
      showToast(err.message || tr('domains.failed_to_create_reality_inbound'), 'error');
    }
  }

  onMount(load);
</script>

<div class="domains-view">
  <h2>{tr('domains.domains')}</h2>

  {#if status && !status.has_domain}
    <!-- The no-domain state is loud, never silent: without a domain, TLS
         protocols cannot be secured, so steer the operator to REALITY. -->
    <div class="banner warn" role="alert">
      <div class="banner-title">{tr('domains.no_domain_configured')}</div>
      <p>{status.guidance_en}</p>
      <p dir="rtl" lang="fa" class="fa">{status.guidance_fa}</p>
      <div class="free-list">
        {#each status.domain_free as p}
          <div class="free-item" class:recommended={p.recommended}>
            <strong>{p.label}{p.recommended ? tr('domains.recommended') : ''}</strong>
            <span>{p.why}</span>
          </div>
        {/each}
      </div>
      <button class="btn-primary" onclick={realityQuickstart}>
        {tr('domains.create_a_reality_inbound_in_one')}
      </button>
    </div>
  {/if}

  <section class="add-domain">
    <h3>{tr('domains.add_a_domain')}</h3>
    <div class="add-row">
      <input placeholder={tr('domains.vpn_example_com')} bind:value={newName} aria-label={tr('domains.domain_name')} />
      <select bind:value={newProvider} aria-label={tr('domains.dns_provider')}>
        <option value="">{tr('domains.no_provider')}</option>
        <option value="cloudflare">Cloudflare</option>
        <option value="arvan">{tr('domains.arvancloud')}</option>
        <option value="desec">{tr('domains.desec')}</option>
      </select>
      <button class="btn-primary" onclick={addDomain} disabled={adding || !newName.trim()}>
        {adding ? tr('domains.adding') : tr('domains.add_domain')}
      </button>
    </div>
    <p class="hint">
      {tr('domains.setting_a_domain_on_an_inbound')}
    </p>
  </section>

  <section class="domain-list">
    <h3>{tr('domains.registered_domains')}</h3>
    {#if loading}
      <p>{tr('domains.loading')}</p>
    {:else if domains.length === 0}
      <p class="empty">{tr('domains.no_domains_yet_add_one_above')}</p>
    {:else}
      <table>
        <thead>
          <tr><th>{tr('domains.domain')}</th><th>{tr('domains.provider')}</th><th>TLS</th><th>{tr('domains.default')}</th><th></th></tr>
        </thead>
        <tbody>
          {#each domains as d}
            <tr>
              <td class="name">{d.name}</td>
              <td>{d.provider || '—'}</td>
              <td>{d.tls_mode || '—'}</td>
              <td>
                {#if d.is_default}
                  <span class="badge">{tr('domains.default_2')}</span>
                {:else}
                  <button class="btn-link" onclick={() => makeDefault(d)}>{tr('domains.make_default')}</button>
                {/if}
              </td>
              <td><button class="btn-danger" onclick={() => removeDomain(d)}>{tr('domains.delete')}</button></td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </section>
</div>

<style>
  .domains-view { padding: 1rem; max-width: 900px; }
  h2 { margin-bottom: 1rem; }
  .banner.warn {
    border: 1px solid var(--warn-2); background: var(--ln-2);
    border-radius: 10px; padding: 1rem; margin-bottom: 1.5rem;
  }
  .banner-title { font-weight: 700; margin-bottom: 0.4rem; }
  .fa { opacity: 0.85; font-size: 0.9rem; }
  .free-list { display: flex; flex-direction: column; gap: 0.4rem; margin: 0.75rem 0; }
  .free-item { display: flex; flex-direction: column; padding: 0.5rem 0.7rem; border-radius: 8px; background: rgba(127,127,127,0.08); }
  .free-item.recommended { border: 1px solid var(--ok); }
  .free-item span { font-size: 0.85rem; opacity: 0.8; }
  .add-row { display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: center; }
  .add-row input, .add-row select { padding: 0.5rem; border-radius: 6px; }
  .hint { font-size: 0.85rem; opacity: 0.75; margin-top: 0.5rem; }
  table { width: 100%; border-collapse: collapse; margin-top: 0.5rem; }
  th, td { text-align: start; padding: 0.5rem; border-bottom: 1px solid rgba(127,127,127,0.2); }
  .name { font-weight: 600; }
  .badge { background: var(--ok); color: var(--on-acc); padding: 0.1rem 0.5rem; border-radius: 10px; font-size: 0.75rem; }
  .btn-primary { background: var(--acc); color: var(--acc-soft); border: none; padding: 0.5rem 0.9rem; border-radius: 6px; cursor: pointer; font-weight: 600; }
  .btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
  .btn-danger { background: transparent; color: var(--bad-2); border: 1px solid var(--bad-2); padding: 0.35rem 0.7rem; border-radius: 6px; cursor: pointer; }
  .btn-link { background: none; border: none; color: var(--acc); cursor: pointer; text-decoration: underline; }
  section { margin-bottom: 1.5rem; }
  .empty { opacity: 0.7; }
</style>
