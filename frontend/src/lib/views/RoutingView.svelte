<script lang="ts">
	import { tr } from '$lib/i18n';
  import { onMount } from 'svelte';
  import { apiFetch } from '$lib/api';
  import Modal from '$lib/components/Modal.svelte';
  import { showToast } from '$lib/components/Toast.svelte';

  // Server-side routing.
  //
  // The panel could send an inbound's whole traffic through one relay chain and
  // nothing else — no blocking, no geo-split, no per-user exit.
  //
  // PRECEDENCE IS SHOWN, not left to be discovered. Rules are first-match and
  // they sit BELOW the per-inbound relay chains, which means a rule cannot pull
  // traffic out of a chain. Someone who assumes the opposite writes "send this
  // domain direct", expects it to apply everywhere, and would be exposing the
  // server's real address if it did.

  interface Outbound {
    id: number;
    tag: string;
    protocol: string;
    settings: any;
    stream_settings: any;
    send_through: string;
    sort_order: number;
    enabled: boolean;
    note: string;
  }
  interface Rule {
    id: number;
    name: string;
    sort_order: number;
    enabled: boolean;
    domain: string[] | null;
    ip: string[] | null;
    port: string;
    network: string;
    protocol: string[] | null;
    inbound_tags: string[] | null;
    user_ids: number[] | null;
    outbound_tag: string;
  }

  let outbounds = $state<Outbound[]>([]);
  let builtin = $state<string[]>(['direct', 'block']);
  let rules = $state<Rule[]>([]);
  let precedence = $state<string[]>([]);
  let loading = $state(true);
  let loadError = $state('');

  const OUTBOUND_PROTOCOLS = [
    'freedom', 'blackhole', 'socks', 'http',
    'vless', 'vmess', 'trojan', 'shadowsocks', 'wireguard'
  ];

  const allTags = $derived([...builtin, ...outbounds.filter((o) => o.enabled).map((o) => o.tag)]);

  async function load() {
    loading = true;
    loadError = '';
    try {
      const [o, r] = await Promise.all([
        apiFetch<{ outbounds: Outbound[]; builtin: string[] }>('/admin/routing/outbounds'),
        apiFetch<{ rules: Rule[]; precedence: string[] }>('/admin/routing/rules')
      ]);
      outbounds = o.outbounds ?? [];
      builtin = o.builtin ?? builtin;
      rules = r.rules ?? [];
      precedence = r.precedence ?? [];
    } catch (err: any) {
      loadError = err.message || tr('routing.failed_to_load_routing');
    } finally {
      loading = false;
    }
  }

  // --- outbound editing ---
  let obOpen = $state(false);
  let obEditing = $state<Outbound | null>(null);
  let obTag = $state('');
  let obProto = $state('freedom');
  let obSettings = $state('');
  let obStream = $state('');
  let obSendThrough = $state('');
  let obNote = $state('');

  function openOutbound(o: Outbound | null) {
    obEditing = o;
    obTag = o?.tag ?? '';
    obProto = o?.protocol ?? 'freedom';
    // Pretty-printed so a stored object is editable rather than one long line.
    obSettings = o?.settings ? JSON.stringify(o.settings, null, 2) : '';
    obStream = o?.stream_settings ? JSON.stringify(o.stream_settings, null, 2) : '';
    obSendThrough = o?.send_through ?? '';
    obNote = o?.note ?? '';
    obOpen = true;
  }

  function parseOrThrow(label: string, text: string): any {
    const t = text.trim();
    if (!t) return null;
    try {
      return JSON.parse(t);
    } catch (e: any) {
      // Sending it anyway would surface as an engine error on the next reload,
      // by which time the operator is nowhere near the field they typed it into.
      throw new Error(`${label} is not valid JSON: ${e.message}`);
    }
  }

  async function saveOutbound() {
    try {
      const body = {
        tag: obTag.trim(),
        protocol: obProto,
        settings: parseOrThrow('Settings', obSettings),
        stream_settings: parseOrThrow('Stream settings', obStream),
        send_through: obSendThrough.trim(),
        note: obNote.trim(),
        enabled: obEditing ? obEditing.enabled : true,
        sort_order: obEditing?.sort_order ?? outbounds.length
      };
      const path = obEditing
        ? `/admin/routing/outbounds/${obEditing.id}`
        : '/admin/routing/outbounds';
      await apiFetch(path, { method: obEditing ? 'PUT' : 'POST', body: JSON.stringify(body) });
      showToast(tr('routing.outbound_saved'), 'success');
      obOpen = false;
      await load();
    } catch (err: any) {
      showToast(err.message || tr('routing.failed_to_save_outbound'), 'error');
    }
  }

  async function deleteOutbound(o: Outbound) {
    if (!confirm(tr('routing.delete_the_outbound_tag', { tag: o.tag }))) return;
    try {
      await apiFetch(`/admin/routing/outbounds/${o.id}`, { method: 'DELETE' });
      showToast(tr('routing.outbound_deleted'), 'success');
      await load();
    } catch (err: any) {
      // The API refuses while a rule still points at it, and says which rules.
      showToast(err.message || tr('routing.failed_to_delete'), 'error');
    }
  }

  // --- rule editing ---
  let ruleOpen = $state(false);
  let rEditing = $state<Rule | null>(null);
  let rName = $state('');
  let rDomain = $state('');
  let rIP = $state('');
  let rPort = $state('');
  let rNetwork = $state('tcp,udp');
  let rProtocol = $state('');
  let rInbounds = $state('');
  let rOutbound = $state('block');

  function lines(v: string[] | null | undefined): string {
    return (v ?? []).join('\n');
  }
  function toList(v: string): string[] {
    return v
      .split(/[\n,]/)
      .map((x) => x.trim())
      .filter(Boolean);
  }

  function openRule(r: Rule | null) {
    rEditing = r;
    rName = r?.name ?? '';
    rDomain = lines(r?.domain);
    rIP = lines(r?.ip);
    rPort = r?.port ?? '';
    rNetwork = r?.network || tr('routing.tcp_udp');
    rProtocol = lines(r?.protocol);
    rInbounds = lines(r?.inbound_tags);
    rOutbound = r?.outbound_tag ?? 'block';
    ruleOpen = true;
  }

  const ruleHasMatcher = $derived(
    !!(rDomain.trim() || rIP.trim() || rPort.trim() || rProtocol.trim() || rInbounds.trim()) ||
      (rNetwork !== '' && rNetwork !== 'tcp,udp')
  );

  async function saveRule() {
    try {
      const body = {
        name: rName.trim() || 'rule',
        domain: toList(rDomain),
        ip: toList(rIP),
        port: rPort.trim(),
        network: rNetwork,
        protocol: toList(rProtocol),
        inbound_tags: toList(rInbounds),
        user_ids: rEditing?.user_ids ?? [],
        outbound_tag: rOutbound,
        enabled: rEditing ? rEditing.enabled : true,
        sort_order: rEditing?.sort_order ?? rules.length
      };
      const path = rEditing ? `/admin/routing/rules/${rEditing.id}` : '/admin/routing/rules';
      await apiFetch(path, { method: rEditing ? 'PUT' : 'POST', body: JSON.stringify(body) });
      showToast(tr('routing.rule_saved'), 'success');
      ruleOpen = false;
      await load();
    } catch (err: any) {
      showToast(err.message || tr('routing.failed_to_save_rule'), 'error');
    }
  }

  async function deleteRule(r: Rule) {
    if (!confirm(tr('routing.delete_the_rule_name', { name: r.name }))) return;
    try {
      await apiFetch(`/admin/routing/rules/${r.id}`, { method: 'DELETE' });
      showToast(tr('routing.rule_deleted'), 'success');
      await load();
    } catch (err: any) {
      showToast(err.message || tr('routing.failed_to_delete'), 'error');
    }
  }

  async function toggleRule(r: Rule) {
    try {
      await apiFetch(`/admin/routing/rules/${r.id}`, {
        method: 'PUT',
        body: JSON.stringify({ ...r, enabled: !r.enabled })
      });
      await load();
    } catch (err: any) {
      showToast(err.message || tr('routing.failed_to_update'), 'error');
    }
  }

  // Reorder sends the COMPLETE list every time. The API refuses a partial one,
  // because an omitted rule keeps whatever position it had — an order nobody
  // designed, live, on a first-match table.
  async function move(i: number, delta: number) {
    const j = i + delta;
    if (j < 0 || j >= rules.length) return;
    const next = [...rules];
    [next[i], next[j]] = [next[j], next[i]];
    try {
      await apiFetch('/admin/routing/rules/reorder', {
        method: 'POST',
        body: JSON.stringify({ ids: next.map((r) => r.id) })
      });
      rules = next;
    } catch (err: any) {
      showToast(err.message || tr('routing.failed_to_reorder'), 'error');
      await load();
    }
  }

  function summarise(r: Rule): string {
    const parts: string[] = [];
    if (r.domain?.length) parts.push(`domain: ${r.domain.slice(0, 2).join(', ')}${r.domain.length > 2 ? '…' : ''}`);
    if (r.ip?.length) parts.push(`ip: ${r.ip.slice(0, 2).join(', ')}${r.ip.length > 2 ? '…' : ''}`);
    if (r.port) parts.push(`port: ${r.port}`);
    if (r.network && r.network !== 'tcp,udp') parts.push(r.network);
    if (r.protocol?.length) parts.push(`proto: ${r.protocol.join(', ')}`);
    if (r.inbound_tags?.length) parts.push(`inbound: ${r.inbound_tags.join(', ')}`);
    if (r.user_ids?.length) parts.push(`${r.user_ids.length} user(s)`);
    return parts.join(' · ') || tr('routing.no_conditions');
  }

  onMount(load);
</script>

<div class="view-header">
  <h2>{tr('routing.routing')}</h2>
  <button class="btn-primary" onclick={load}>{tr('routing.refresh')}</button>
</div>

{#if precedence.length}
  <!-- Stated, not inferred. Getting this wrong can pull traffic out of a relay
       chain and expose the server's real address. -->
  <div class="card precedence" data-testid="precedence">
    <h3>{tr('routing.evaluation_order')}</h3>
    <ol>
      {#each precedence as step}<li>{step}</li>{/each}
    </ol>
    <p class="muted">
      {tr('routing.first_match_wins_rules_sit_below')}
    </p>
  </div>
{/if}

{#if loadError}
  <div class="card"><p class="err-text">{loadError}</p></div>
{:else if loading}
  <div class="card"><p class="muted">{tr('routing.loading')}</p></div>
{:else}
  <div class="card">
    <div class="section-head">
      <h3>{tr('routing.outbounds')}</h3>
      <button class="btn-primary" data-testid="new-outbound" onclick={() => openOutbound(null)}>
        {tr('routing.new_outbound')}
      </button>
    </div>
    <p class="muted">
      {tr('routing.built_in_and_always_available_unmatched', { p1: builtin.join(', ') })} <code>{tr('routing.direct')}</code>.
    </p>
    {#if outbounds.length}
      <table>
        <thead><tr><th>{tr('routing.tag')}</th><th>{tr('routing.protocol')}</th><th>{tr('routing.send_through')}</th><th>{tr('routing.note')}</th><th></th></tr></thead>
        <tbody>
          {#each outbounds as o}
            <tr class:off={!o.enabled}>
              <td><code>{o.tag}</code></td>
              <td>{o.protocol}</td>
              <td class="mono">{o.send_through || '—'}</td>
              <td class="note">{o.note || '—'}</td>
              <td class="acts">
                <button class="btn-sm" onclick={() => openOutbound(o)}>{tr('routing.edit')}</button>
                <button class="btn-sm danger" onclick={() => deleteOutbound(o)}>{tr('routing.delete')}</button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </div>

  <div class="card">
    <div class="section-head">
      <h3>{tr('routing.rules')}</h3>
      <button class="btn-primary" data-testid="new-rule" onclick={() => openRule(null)}>{tr('routing.new_rule')}</button>
    </div>
    {#if rules.length === 0}
      <p class="muted" data-testid="no-rules">
        {tr('routing.no_rules_yet_without_any_every')}
      </p>
    {:else}
      <table>
        <thead><tr><th>#</th><th>{tr('routing.rule')}</th><th>{tr('routing.matches')}</th><th>{tr('routing.sends_to')}</th><th></th></tr></thead>
        <tbody>
          {#each rules as r, i}
            <tr class:off={!r.enabled}>
              <td class="mono">{i + 1}</td>
              <td><strong>{r.name}</strong></td>
              <td class="muted">{summarise(r)}</td>
              <td><code>{r.outbound_tag}</code></td>
              <td class="acts">
                <button class="btn-sm" disabled={i === 0} onclick={() => move(i, -1)} title={tr('routing.earlier')}>↑</button>
                <button class="btn-sm" disabled={i === rules.length - 1} onclick={() => move(i, 1)} title={tr('routing.later')}>↓</button>
                <button class="btn-sm" data-testid="toggle-rule" onclick={() => toggleRule(r)}>
                  {r.enabled ? 'Disable' : 'Enable'}
                </button>
                <button class="btn-sm" onclick={() => openRule(r)}>{tr('routing.edit')}</button>
                <button class="btn-sm danger" onclick={() => deleteRule(r)}>{tr('routing.delete')}</button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </div>
{/if}

<Modal title={obEditing ? 'Edit outbound' : 'New outbound'} isOpen={obOpen} onClose={() => (obOpen = false)}>
  <label>{tr('routing.tag')}<input bind:value={obTag} placeholder={tr('routing.relay_de')} data-testid="ob-tag" /></label>
  <label>
    {tr('routing.protocol')}
    <select bind:value={obProto} data-testid="ob-proto">
      {#each OUTBOUND_PROTOCOLS as p}<option value={p}>{p}</option>{/each}
    </select>
  </label>
  <label>
    {tr('routing.settings_json')}
    <textarea bind:value={obSettings} rows="6" data-testid="ob-settings"
      placeholder={'{"servers":[{"address":"127.0.0.1","port":1080}]}'}></textarea>
    <small>{tr('routing.the_core_s_own_object_passed')}</small>
  </label>
  <label>
    {tr('routing.stream_settings_json')}
    <textarea bind:value={obStream} rows="4" placeholder={'{"network":"tcp"}'}></textarea>
  </label>
  <label>
    {tr('routing.send_through')}
    <input bind:value={obSendThrough} placeholder="10.0.0.5" />
    <small>{tr('routing.local_source_address_for_a_host')}</small>
  </label>
  <label>{tr('routing.note')}<input bind:value={obNote} placeholder={tr('routing.what_this_exit_is_for')} /></label>
  <div class="modal-actions">
    <button class="btn-sm" onclick={() => (obOpen = false)}>{tr('routing.cancel')}</button>
    <button class="btn-primary" data-testid="save-outbound" onclick={saveOutbound}>{tr('routing.save')}</button>
  </div>
</Modal>

<Modal title={rEditing ? 'Edit rule' : 'New rule'} isOpen={ruleOpen} onClose={() => (ruleOpen = false)}>
  <label>{tr('routing.name')}<input bind:value={rName} placeholder={tr('routing.block_ads')} data-testid="rule-name" /></label>
  <label>
    {tr('routing.domains')}
    <textarea bind:value={rDomain} rows="3" data-testid="rule-domain"
      placeholder={'geosite:category-ads-all\ndomain:example.com'}></textarea>
  </label>
  <label>
    {tr('routing.ips')}
    <textarea bind:value={rIP} rows="3" placeholder={'geoip:ir\n10.0.0.0/8'}></textarea>
  </label>
  <label>{tr('routing.ports')}<input bind:value={rPort} placeholder="80,443,1000-2000" /></label>
  <label>
    {tr('routing.network')}
    <select bind:value={rNetwork}>
      <option value="tcp,udp">{tr('routing.tcp_and_udp')}</option>
      <option value="tcp">{tr('routing.tcp')}</option>
      <option value="udp">{tr('routing.udp')}</option>
    </select>
  </label>
  <label>
    {tr('routing.sniffed_protocols')}
    <textarea bind:value={rProtocol} rows="2" placeholder={'tls\nbittorrent'}></textarea>
    <!-- A rule matching on a sniffed protocol silently never fires when
         sniffing is off for the inbound, which reads as a broken panel. -->
    <small>{tr('routing.only_matches_when_sniffing_is_enabled')}</small>
  </label>
  <label>
    {tr('routing.inbound_tags')}
    <textarea bind:value={rInbounds} rows="2" placeholder={tr('routing.in_443')}></textarea>
  </label>
  <label>
    {tr('routing.send_to')}
    <select bind:value={rOutbound} data-testid="rule-outbound">
      {#each allTags as t}<option value={t}>{t}</option>{/each}
    </select>
  </label>
  {#if !ruleHasMatcher}
    <!-- The API refuses this too; saying so here means the operator finds out
         while looking at the form rather than from a rejected request. -->
    <p class="warn" data-testid="rule-warning">
      {tr('routing.a_rule_with_no_conditions_matches')}
    </p>
  {/if}
  <div class="modal-actions">
    <button class="btn-sm" onclick={() => (ruleOpen = false)}>{tr('routing.cancel')}</button>
    <button class="btn-primary" data-testid="save-rule" disabled={!ruleHasMatcher} onclick={saveRule}>
      {tr('routing.save')}
    </button>
  </div>
</Modal>

<style>
  .view-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
  .view-header h2 { margin: 0; font-size: 20px; font-weight: 650; }
  .card { background: #141A24; border: 1px solid rgba(255,255,255,0.08); border-radius: 14px; padding: 20px; margin-bottom: 20px; }
  .card h3 { margin: 0; font-size: 13px; text-transform: uppercase; color: rgba(255,255,255,0.7); }
  .section-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
  .precedence ol { margin: 10px 0; padding-inline-start: 20px; color: rgba(255,255,255,0.8); font-size: 13px; line-height: 1.8; }
  table { width: 100%; border-collapse: collapse; margin-top: 12px; }
  th, td { text-align: start; padding: 9px 12px; border-bottom: 1px solid rgba(255,255,255,0.06); font-size: 13px; }
  th { color: rgba(255,255,255,0.55); font-weight: 600; text-transform: uppercase; font-size: 11px; }
  tr.off td { opacity: 0.45; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; background: rgba(255,255,255,0.06); padding: 2px 6px; border-radius: 4px; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
  .note { max-width: 240px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .muted { color: rgba(255,255,255,0.55); font-size: 13px; margin: 0; }
  .err-text { color: #f85149; font-size: 13px; }
  .warn { color: #d99b2b; font-size: 12px; line-height: 1.6; margin: 4px 0 0; }
  .acts { display: flex; gap: 6px; }
  label { display: block; margin-bottom: 12px; font-size: 12px; color: rgba(255,255,255,0.7); }
  label small { display: block; margin-top: 4px; color: rgba(255,255,255,0.45); font-size: 11px; }
  input, select, textarea { width: 100%; background: #0F1420; border: 1px solid rgba(255,255,255,0.12); color: #fff; padding: 9px; border-radius: 8px; font: inherit; margin-top: 4px; }
  textarea { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; resize: vertical; }
  .modal-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 16px; }
  .btn-primary { background: #FF7A1A; color: #10141c; padding: 9px 16px; font-weight: 600; border: 0; border-radius: 8px; cursor: pointer; font: inherit; }
  .btn-primary:disabled { opacity: 0.4; cursor: default; }
  .btn-sm { background: rgba(255,255,255,0.08); color: #fff; padding: 4px 10px; font-size: 12px; border: 0; border-radius: 8px; cursor: pointer; font: inherit; }
  .btn-sm:disabled { opacity: 0.3; cursor: default; }
  .btn-sm.danger { background: rgba(248,81,73,0.16); color: #f85149; }
</style>
