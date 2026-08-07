<script lang="ts">
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
      showToast(err.message || 'Failed to load domains', 'error');
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
      showToast(`Domain ${name} added`, 'success');
      newName = '';
      newProvider = '';
      await load();
    } catch (err: any) {
      showToast(err.message || 'Failed to add domain', 'error');
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
      showToast(`${d.name} is now the default domain`, 'success');
      await load();
    } catch (err: any) {
      showToast(err.message || 'Failed', 'error');
    }
  }

  async function removeDomain(d: Domain) {
    if (!confirm(`Delete ${d.name}? Inbounds using it will keep the bare domain string.`)) return;
    try {
      await apiFetch(`/admin/domains/${d.id}`, { method: 'DELETE' });
      showToast(`${d.name} deleted`, 'success');
      await load();
    } catch (err: any) {
      if (err.status === 409) {
        if (confirm(`${d.name} is still used by inbounds. Delete anyway?`)) {
          try {
            await apiFetch(`/admin/domains/${d.id}?force=true`, { method: 'DELETE' });
            showToast(`${d.name} deleted`, 'success');
            await load();
          } catch (e: any) {
            showToast(e.message || 'Failed', 'error');
          }
        }
      } else {
        showToast(err.message || 'Failed', 'error');
      }
    }
  }

  async function realityQuickstart() {
    try {
      const res = await apiFetch<{ port: number }>('/admin/inbounds/reality-quickstart', {
        method: 'POST',
        body: JSON.stringify({})
      });
      showToast(`REALITY inbound created on port ${res.port}`, 'success');
    } catch (err: any) {
      showToast(err.message || 'Failed to create REALITY inbound', 'error');
    }
  }

  onMount(load);
</script>

<div class="domains-view">
  <h2>Domains</h2>

  {#if status && !status.has_domain}
    <!-- The no-domain state is loud, never silent: without a domain, TLS
         protocols cannot be secured, so steer the operator to REALITY. -->
    <div class="banner warn" role="alert">
      <div class="banner-title">⚠️ No domain configured</div>
      <p>{status.guidance_en}</p>
      <p dir="rtl" lang="fa" class="fa">{status.guidance_fa}</p>
      <div class="free-list">
        {#each status.domain_free as p}
          <div class="free-item" class:recommended={p.recommended}>
            <strong>{p.label}{p.recommended ? ' — recommended' : ''}</strong>
            <span>{p.why}</span>
          </div>
        {/each}
      </div>
      <button class="btn-primary" onclick={realityQuickstart}>
        Create a REALITY inbound in one click
      </button>
    </div>
  {/if}

  <section class="add-domain">
    <h3>Add a domain</h3>
    <div class="add-row">
      <input placeholder="vpn.example.com" bind:value={newName} aria-label="Domain name" />
      <select bind:value={newProvider} aria-label="DNS provider">
        <option value="">No provider</option>
        <option value="cloudflare">Cloudflare</option>
        <option value="arvan">ArvanCloud</option>
        <option value="desec">deSEC</option>
      </select>
      <button class="btn-primary" onclick={addDomain} disabled={adding || !newName.trim()}>
        {adding ? 'Adding…' : 'Add domain'}
      </button>
    </div>
    <p class="hint">
      Setting a domain on an inbound cascades to its SNI, Host header, certificate,
      generated client links and subscription URL — set it once, everything follows.
    </p>
  </section>

  <section class="domain-list">
    <h3>Registered domains</h3>
    {#if loading}
      <p>Loading…</p>
    {:else if domains.length === 0}
      <p class="empty">No domains yet — add one above to unlock one-click TLS.</p>
    {:else}
      <table>
        <thead>
          <tr><th>Domain</th><th>Provider</th><th>TLS</th><th>Default</th><th></th></tr>
        </thead>
        <tbody>
          {#each domains as d}
            <tr>
              <td class="name">{d.name}</td>
              <td>{d.provider || '—'}</td>
              <td>{d.tls_mode || '—'}</td>
              <td>
                {#if d.is_default}
                  <span class="badge">default</span>
                {:else}
                  <button class="btn-link" onclick={() => makeDefault(d)}>make default</button>
                {/if}
              </td>
              <td><button class="btn-danger" onclick={() => removeDomain(d)}>Delete</button></td>
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
    border: 1px solid #e8a33d; background: rgba(232, 163, 61, 0.1);
    border-radius: 10px; padding: 1rem; margin-bottom: 1.5rem;
  }
  .banner-title { font-weight: 700; margin-bottom: 0.4rem; }
  .fa { opacity: 0.85; font-size: 0.9rem; }
  .free-list { display: flex; flex-direction: column; gap: 0.4rem; margin: 0.75rem 0; }
  .free-item { display: flex; flex-direction: column; padding: 0.5rem 0.7rem; border-radius: 8px; background: rgba(127,127,127,0.08); }
  .free-item.recommended { border: 1px solid #27d17c; }
  .free-item span { font-size: 0.85rem; opacity: 0.8; }
  .add-row { display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: center; }
  .add-row input, .add-row select { padding: 0.5rem; border-radius: 6px; }
  .hint { font-size: 0.85rem; opacity: 0.75; margin-top: 0.5rem; }
  table { width: 100%; border-collapse: collapse; margin-top: 0.5rem; }
  th, td { text-align: left; padding: 0.5rem; border-bottom: 1px solid rgba(127,127,127,0.2); }
  .name { font-weight: 600; }
  .badge { background: #27d17c; color: #04140a; padding: 0.1rem 0.5rem; border-radius: 10px; font-size: 0.75rem; }
  .btn-primary { background: #ff7a1a; color: #1a1204; border: none; padding: 0.5rem 0.9rem; border-radius: 6px; cursor: pointer; font-weight: 600; }
  .btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
  .btn-danger { background: transparent; color: #e5484d; border: 1px solid #e5484d; padding: 0.35rem 0.7rem; border-radius: 6px; cursor: pointer; }
  .btn-link { background: none; border: none; color: #7dd3fc; cursor: pointer; text-decoration: underline; }
  section { margin-bottom: 1.5rem; }
  .empty { opacity: 0.7; }
</style>
