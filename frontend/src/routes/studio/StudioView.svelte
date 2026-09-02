<script lang="ts">
	import { tr } from '$lib/i18n';
  import { onMount } from 'svelte';
  import { apiFetch } from '$lib/api';
  import InboundForm from '$lib/components/InboundForm.svelte';
  import { showToast } from '$lib/components/Toast.svelte';

  interface Preset {
    id: string; name: string; description: string;
    engine: string; cdn: boolean; node: Record<string, any>;
  }

  // The presets come from GET /protocols/presets, which is the only place that
  // knows which COMBINATIONS work. The studio used to hardcode ten protocol-only
  // shortcuts that set nothing but the protocol and left the rest to the form's
  // defaults — so the button labelled "VLESS + REALITY" selected vless and
  // whatever security the schema happened to default to, and the entry labelled
  // for a transport never chose one. The server's presets are complete nodes,
  // each one validated against the pinned engines by TestPresetsAreValid.
  //
  // name is the server's, because "VLESS · REALITY · Vision" is a list of
  // protocol names and translating one stops it matching the config the panel
  // writes. The DESCRIPTION is a sentence, so it comes from the catalogue, keyed
  // by preset id — with the server's English as the fallback for a preset this
  // build has no translation for yet, which is better than showing an operator
  // a raw key. TestStudioPresetsAllHaveDescriptions keeps the two in step.
  const DESC_KEYS = [
    { id: 'vless-reality-vision', descKey: 'studio.preset.vless-reality-vision.desc' },
    { id: 'vless-ws-tls-cdn', descKey: 'studio.preset.vless-ws-tls-cdn.desc' },
    { id: 'vless-xhttp-tls-cdn', descKey: 'studio.preset.vless-xhttp-tls-cdn.desc' },
    { id: 'vless-grpc-tls', descKey: 'studio.preset.vless-grpc-tls.desc' },
    { id: 'vmess-ws-tls', descKey: 'studio.preset.vmess-ws-tls.desc' },
    { id: 'vmess-xhttp-tls', descKey: 'studio.preset.vmess-xhttp-tls.desc' },
    { id: 'trojan-tcp-tls', descKey: 'studio.preset.trojan-tcp-tls.desc' },
    { id: 'trojan-ws-tls-cdn', descKey: 'studio.preset.trojan-ws-tls-cdn.desc' },
    { id: 'trojan-xhttp-tls-cdn', descKey: 'studio.preset.trojan-xhttp-tls-cdn.desc' },
    { id: 'shadowsocks-2022', descKey: 'studio.preset.shadowsocks-2022.desc' },
    { id: 'hysteria2', descKey: 'studio.preset.hysteria2.desc' },
    { id: 'tuic', descKey: 'studio.preset.tuic.desc' },
    { id: 'anytls', descKey: 'studio.preset.anytls.desc' },
    { id: 'shadowtls', descKey: 'studio.preset.shadowtls.desc' },
    { id: 'wireguard', descKey: 'studio.preset.wireguard.desc' },
    { id: 'amneziawg', descKey: 'studio.preset.amneziawg.desc' },
    { id: 'brook-wss', descKey: 'studio.preset.brook-wss.desc' },
  ];
  const descKeyFor = (id: string) => DESC_KEYS.find((d) => d.id === id)?.descKey;
  function describe(p: Preset): string {
    const k = descKeyFor(p.id);
    return k ? tr(k) : p.description;
  }

  let presets = $state<Preset[]>([]);
  let loadError = $state('');
  let selected = $state<Preset | null>(null);
  // remount the form when the preset changes so it re-seeds from the new node
  let formKey = $state(0);

  function pick(p: Preset) {
    selected = p;
    formKey++;
  }

  onMount(async () => {
    try {
      const res = await apiFetch<{ presets: Preset[] }>('/protocols/presets');
      presets = res.presets ?? [];
      if (presets.length) pick(presets[0]);
    } catch (e: any) {
      loadError = e.message || tr('studio.presets_failed');
    }
  });
</script>

<div class="head">
  <h2>{tr('studio.config_studio_amp_protocol_engine')}</h2>
  <span class="sub">{tr('studio.build_any_protocol_see_the_client')}</span>
</div>

<div class="layout">
  <div class="card presets" data-testid="studio-presets">
    <h3>{tr('studio.presets')}</h3>
    {#if loadError}
      <p class="err" data-testid="studio-presets-error">{loadError}</p>
    {:else if presets.length === 0}
      <p class="d">{tr('studio.loading_presets')}</p>
    {/if}
    {#each presets as p (p.id)}
      <button class="preset" data-testid="studio-preset" data-preset={p.id}
              class:sel={selected?.id === p.id} onclick={() => pick(p)}>
        <strong>{p.name}</strong>
        <span class="d">{describe(p)}</span>
        <span class="tags">
          <span class="tag">{p.engine}</span>
          {#if p.cdn}<span class="tag cdn" data-testid="preset-cdn">{tr('studio.cdn')}</span>{/if}
        </span>
      </button>
    {/each}
  </div>

  <div class="card builder-card">
    {#key formKey}
      {#if selected}
        <InboundForm initialProto={selected.node.protocol} initial={selected.node}
                     onSaved={() => showToast(tr('studio.saved_as_inbound_see_the_inbounds'), 'success')} />
      {/if}
    {/key}
  </div>
</div>

<style>
  .head { margin-bottom: 20px; }
  .head h2 { margin: 0; font-size: 20px; }
  .sub { font-size: 13px; color: var(--t-7); }
  .layout { display: grid; grid-template-columns: 240px 1fr; gap: 20px; align-items: start; }
  @media (max-width: 900px) { .layout { grid-template-columns: 1fr; } }
  .card { background: var(--card); border: 1px solid var(--ln-3); border-radius: 14px; padding: 18px; }
  .card h3 { margin: 0 0 14px; font-size: 12px; text-transform: uppercase; color: var(--t-5); }
  .preset { display: flex; flex-direction: column; gap: 3px; width: 100%; text-align: start; background: var(--bg); border: 1px solid var(--ln-3); border-radius: 8px; padding: 10px 12px; margin-bottom: 8px; color: var(--fg); cursor: pointer; }
  .preset:hover, .preset.sel { border-color: var(--acc); background: rgba(255,122,26,0.1); }
  .preset .d { font-size: 11px; color: var(--t-7); }
  .tags { display: flex; gap: 6px; margin-top: 4px; }
  .tag { font-size: 10px; text-transform: uppercase; letter-spacing: 0.03em; padding: 1px 6px; border-radius: 4px; background: var(--ln-3); color: var(--t-4); }
  .tag.cdn { background: rgba(255,122,26,0.18); color: var(--acc-2); }
  .err { font-size: 12px; color: var(--bad-3); }
</style>
