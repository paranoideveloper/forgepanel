<script lang="ts">
  import InboundForm from '$lib/components/InboundForm.svelte';
  import { showToast } from '$lib/components/Toast.svelte';

  // A few one-click starting points; each just sets the initial protocol and the
  // form (schema-driven) fills the rest. The live preview + Save are the real
  // Config Studio — every field of every protocol, four formats, working save.
  const presets = [
    { proto: 'vless', label: 'VLESS + REALITY', desc: 'Vision/REALITY, no domain needed' },
    { proto: 'vmess', label: 'VMess', desc: 'AEAD VMess over any transport' },
    { proto: 'trojan', label: 'Trojan', desc: 'Trojan over TLS/REALITY' },
    { proto: 'shadowsocks', label: 'Shadowsocks 2022', desc: 'SS2022 symmetric, no TLS' },
    { proto: 'hysteria2', label: 'Hysteria2', desc: 'QUIC, self-signed + pin' },
    { proto: 'tuic', label: 'TUIC v5', desc: 'QUIC, BBR' },
    { proto: 'anytls', label: 'AnyTLS', desc: 'TLS multiplexed' },
    { proto: 'shadowtls', label: 'ShadowTLS', desc: 'TLS camouflage + inner SS' },
    { proto: 'wireguard', label: 'WireGuard', desc: 'Key-based, no TLS' },
    { proto: 'brook', label: 'Brook', desc: 'server/ws/wss/quic' },
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
  <h2>Config Studio &amp; Protocol Engine</h2>
  <span class="sub">Build any protocol, see the client link + Xray + sing-box + Clash live, then save it as an inbound.</span>
</div>

<div class="layout">
  <div class="card presets" data-testid="studio-presets">
    <h3>Presets</h3>
    {#each presets as p}
      <button class="preset" class:sel={selected === p.proto} onclick={() => pick(p.proto)}>
        <strong>{p.label}</strong>
        <span class="d">{p.desc}</span>
      </button>
    {/each}
  </div>

  <div class="card builder-card">
    {#key formKey}
      <InboundForm initialProto={selected} onSaved={() => showToast('Saved as inbound — see the Inbounds tab', 'success')} />
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
  .preset { display: flex; flex-direction: column; gap: 3px; width: 100%; text-align: left; background: #0F1420; border: 1px solid rgba(255,255,255,0.08); border-radius: 8px; padding: 10px 12px; margin-bottom: 8px; color: #fff; cursor: pointer; }
  .preset:hover, .preset.sel { border-color: #FF7A1A; background: rgba(255,122,26,0.1); }
  .preset .d { font-size: 11px; color: rgba(255,255,255,0.5); }
</style>
