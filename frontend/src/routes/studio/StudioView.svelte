<script lang="ts">
	import { tr } from '$lib/i18n';
  import InboundForm from '$lib/components/InboundForm.svelte';
  import { showToast } from '$lib/components/Toast.svelte';

  // A few one-click starting points; each just sets the initial protocol and the
  // form (schema-driven) fills the rest. The live preview + Save are the real
  // Config Studio — every field of every protocol, four formats, working save.
  // label stays literal: 'VLESS + REALITY' is the protocol's name, and a
  // translated protocol name no longer matches the config the panel writes or
  // the documentation an operator is reading. descKey is translated at render
  // time for the same reason the sidebar uses labelKey.
  const presets = [
    { proto: 'vless', label: 'VLESS + REALITY', descKey: 'studio.preset.vless.desc' },
    { proto: 'vmess', label: 'VMess', descKey: 'studio.preset.vmess.desc' },
    { proto: 'trojan', label: 'Trojan', descKey: 'studio.preset.trojan.desc' },
    { proto: 'shadowsocks', label: 'Shadowsocks 2022', descKey: 'studio.preset.shadowsocks.desc' },
    { proto: 'hysteria2', label: 'Hysteria2', descKey: 'studio.preset.hysteria2.desc' },
    { proto: 'tuic', label: 'TUIC v5', descKey: 'studio.preset.tuic.desc' },
    { proto: 'anytls', label: 'AnyTLS', descKey: 'studio.preset.anytls.desc' },
    { proto: 'shadowtls', label: 'ShadowTLS', descKey: 'studio.preset.shadowtls.desc' },
    { proto: 'wireguard', label: 'WireGuard', descKey: 'studio.preset.wireguard.desc' },
    { proto: 'brook', label: 'Brook', descKey: 'studio.preset.brook.desc' },
  ];

  let selected = $state('vless');
  // remount the form when the preset changes so it re-seeds defaults
  let formKey = $state(0);

  function pick(p: string) {
    selected = p;
    formKey++;
  }
</script>

<div class="head">
  <h2>{tr('studio.config_studio_amp_protocol_engine')}</h2>
  <span class="sub">{tr('studio.build_any_protocol_see_the_client')}</span>
</div>

<div class="layout">
  <div class="card presets" data-testid="studio-presets">
    <h3>{tr('studio.presets')}</h3>
    {#each presets as p}
      <button class="preset" class:sel={selected === p.proto} onclick={() => pick(p.proto)}>
        <strong>{p.label}</strong>
        <span class="d">{tr(p.descKey)}</span>
      </button>
    {/each}
  </div>

  <div class="card builder-card">
    {#key formKey}
      <InboundForm initialProto={selected} onSaved={() => showToast(tr('studio.saved_as_inbound_see_the_inbounds'), 'success')} />
    {/key}
  </div>
</div>

<style>
  .head { margin-bottom: 20px; }
  .head h2 { margin: 0; font-size: 20px; }
  .sub { font-size: 13px; color: rgba(255,255,255,0.5); }
  .layout { display: grid; grid-template-columns: 220px 1fr; gap: 20px; align-items: start; }
  @media (max-width: 900px) { .layout { grid-template-columns: 1fr; } }
  .card { background: #141A24; border: 1px solid rgba(255,255,255,0.08); border-radius: 14px; padding: 18px; }
  .card h3 { margin: 0 0 14px; font-size: 12px; text-transform: uppercase; color: rgba(255,255,255,0.6); }
  .preset { display: flex; flex-direction: column; gap: 3px; width: 100%; text-align: start; background: #0F1420; border: 1px solid rgba(255,255,255,0.08); border-radius: 8px; padding: 10px 12px; margin-bottom: 8px; color: #fff; cursor: pointer; }
  .preset:hover, .preset.sel { border-color: #FF7A1A; background: rgba(255,122,26,0.1); }
  .preset .d { font-size: 11px; color: rgba(255,255,255,0.5); }
</style>
