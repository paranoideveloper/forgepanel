<script lang="ts">
  import { onMount } from 'svelte';
  import { tr } from '$lib/i18n';
  import { apiFetch } from '$lib/api';
  import { showToast } from '$lib/components/Toast.svelte';

  let { inboundId } = $props<{ inboundId: number }>();

  interface Host {
    id?: number;
    label: string;
    remark: string;
    address: string;
    port: number;
    security: string;
    sni: string;
    host_header: string;
    path: string;
    alpn: string;
    fingerprint: string;
    allow_insecure: boolean;
    enabled: boolean;
    priority: number;
  }

  const blank = (): Host => ({
    label: '', remark: '', address: '', port: 0, security: '', sni: '',
    host_header: '', path: '', alpn: '', fingerprint: '', allow_insecure: false,
    enabled: true, priority: 0
  });

  let hosts = $state<Host[]>([]);
  let loading = $state(true);
  let draft = $state<Host | null>(null);

  const fingerprints = ['', 'chrome', 'firefox', 'safari', 'ios', 'android', 'edge', 'random'];

  async function load() {
    loading = true;
    try {
      const res = await apiFetch<{ hosts: Host[] }>(`/admin/inbounds/${inboundId}/hosts`);
      hosts = res.hosts ?? [];
    } catch (e: any) {
      showToast(e.message || tr('hosts.failed_to_load'), 'error');
    } finally {
      loading = false;
    }
  }
  onMount(load);

  async function save() {
    if (!draft) return;
    const body = JSON.stringify(draft);
    try {
      if (draft.id) {
        await apiFetch(`/admin/inbounds/${inboundId}/hosts/${draft.id}`, { method: 'PUT', body });
      } else {
        await apiFetch(`/admin/inbounds/${inboundId}/hosts`, { method: 'POST', body });
      }
      draft = null;
      showToast(tr('hosts.saved'), 'success');
      load();
    } catch (e: any) {
      showToast(e.message || tr('hosts.failed_to_save'), 'error');
    }
  }

  async function remove(h: Host) {
    if (!confirm(tr('hosts.delete_confirm', { label: h.label || String(h.id) }))) return;
    try {
      await apiFetch(`/admin/inbounds/${inboundId}/hosts/${h.id}`, { method: 'DELETE' });
      showToast(tr('hosts.deleted'), 'success');
      load();
    } catch (e: any) {
      showToast(e.message || tr('hosts.failed_to_delete'), 'error');
    }
  }
</script>

<div class="hosts">
  <p class="hint">{tr('hosts.explainer')}</p>

  {#if loading}
    <p class="muted">{tr('hosts.loading')}</p>
  {:else if hosts.length === 0}
    <p class="muted">{tr('hosts.empty')}</p>
  {:else}
    <table>
      <thead>
        <tr>
          <th>{tr('hosts.label')}</th>
          <th>{tr('hosts.address')}</th>
          <th>{tr('hosts.port')}</th>
          <th>{tr('hosts.security')}</th>
          <th>{tr('hosts.sni')}</th>
          <th>{tr('hosts.host_header')}</th>
          <th>{tr('hosts.status')}</th>
          <th>{tr('hosts.actions')}</th>
        </tr>
      </thead>
      <tbody>
        {#each hosts as h}
          <tr class:off={!h.enabled}>
            <td>{h.label || '—'}</td>
            <td>{h.address || tr('hosts.inherited')}</td>
            <td>{h.port || tr('hosts.inherited')}</td>
            <td>{h.security || tr('hosts.inherited')}</td>
            <td>{h.sni || tr('hosts.inherited')}</td>
            <td>{h.host_header || tr('hosts.inherited')}</td>
            <td>{h.enabled ? tr('hosts.enabled') : tr('hosts.parked')}</td>
            <td class="row-actions">
              <button class="sm" onclick={() => (draft = { ...h })}>{tr('hosts.edit')}</button>
              <button class="sm danger" onclick={() => remove(h)}>{tr('hosts.delete')}</button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}

  <button class="btn-secondary" onclick={() => (draft = blank())}>{tr('hosts.add')}</button>

  {#if draft}
    <div class="editor">
      <h4>{draft.id ? tr('hosts.edit_endpoint') : tr('hosts.new_endpoint')}</h4>
      <p class="hint">{tr('hosts.blank_inherits')}</p>
      <div class="grid">
        <label>{tr('hosts.label')}<input bind:value={draft.label} placeholder={tr('hosts.label_placeholder')} /></label>
        <label>{tr('hosts.remark')}<input bind:value={draft.remark} placeholder={tr('hosts.remark_placeholder')} /></label>
        <label>{tr('hosts.address')}<input bind:value={draft.address} placeholder={tr('hosts.inherited')} /></label>
        <label>{tr('hosts.port')}<input type="number" bind:value={draft.port} placeholder="0" /></label>
        <label>{tr('hosts.security')}
          <select bind:value={draft.security}>
            <option value="">{tr('hosts.inherited')}</option>
            <option value="none">none</option>
            <option value="tls">tls</option>
            <option value="reality">reality</option>
          </select>
        </label>
        <label>{tr('hosts.fingerprint')}
          <select bind:value={draft.fingerprint}>
            {#each fingerprints as fp}
              <option value={fp}>{fp === '' ? tr('hosts.inherited') : fp}</option>
            {/each}
          </select>
        </label>
        <label>{tr('hosts.sni')}<input bind:value={draft.sni} placeholder={tr('hosts.inherited')} /></label>
        <label>{tr('hosts.host_header')}<input bind:value={draft.host_header} placeholder={tr('hosts.inherited')} /></label>
        <label>{tr('hosts.path')}<input bind:value={draft.path} placeholder={tr('hosts.inherited')} /></label>
        <label>{tr('hosts.alpn')}<input bind:value={draft.alpn} placeholder="h2,http/1.1" /></label>
        <label>{tr('hosts.priority')}<input type="number" bind:value={draft.priority} /></label>
      </div>
      <label class="check"><input type="checkbox" bind:checked={draft.allow_insecure} /> {tr('hosts.allow_insecure')}</label>
      <p class="hint">{tr('hosts.allow_insecure_hint')}</p>
      <label class="check"><input type="checkbox" bind:checked={draft.enabled} /> {tr('hosts.enabled_label')}</label>
      <div class="row-actions">
        <button class="btn-primary" onclick={save}>{tr('hosts.save')}</button>
        <button class="btn-secondary" onclick={() => (draft = null)}>{tr('hosts.cancel')}</button>
      </div>
    </div>
  {/if}
</div>

<style>
  .hosts { margin-top: 12px; }
  .hint { color: var(--t-5); font-size: 12px; line-height: 1.6; margin: 6px 0; }
  .muted { color: var(--t-7); font-size: 13px; }
  table { width: 100%; border-collapse: collapse; margin-bottom: 10px; }
  th, td { text-align: start; padding: 8px 10px; border-bottom: 1px solid var(--ln-3); font-size: 13px; }
  tr.off td { opacity: 0.45; }
  .editor { margin-top: 12px; padding: 12px; border: 1px solid var(--ln-4); border-radius: 8px; background: var(--bg); }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; }
  label { display: flex; flex-direction: column; gap: 4px; font-size: 12px; color: var(--t-2); }
  label.check { flex-direction: row; align-items: center; gap: 8px; margin-top: 10px; }
  input, select { padding: 7px 9px; border-radius: 6px; border: 1px solid var(--ln-5); background: var(--bg-deep); color: var(--fg); font-size: 13px; }
  .row-actions { display: flex; gap: 6px; margin-top: 12px; }
</style>
