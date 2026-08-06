<script lang="ts">
  import { onMount } from 'svelte';
  import { apiFetch } from '$lib/api';
  import type { ProtocolPreset, KeygenResult } from '$lib/types';
  import { showToast } from '$lib/components/Toast.svelte';

  let presets = $state<ProtocolPreset[]>([]);
  let selectedPreset = $state<ProtocolPreset | null>(null);
  let keygenData = $state<KeygenResult | null>(null);
  let configJson = $state<string>('');

  let listenPort = $state(443);
  let sniDomain = $state('example.com');
  let targetEngine = $state('xray');

  async function loadPresets() {
    try {
      presets = await apiFetch<ProtocolPreset[]>('/protocols/presets');
      if (presets.length > 0) {
        selectPreset(presets[0]);
      }
    } catch (_) {
      presets = [
        { id: 'vless-reality', name: 'VLESS Reality (Xray)', engine: 'xray', description: 'VLESS + Vision + REALITY TLS', config: {} },
        { id: 'tuic-v5', name: 'TUIC v5 (Native)', engine: 'tuic', description: 'TUIC over QUIC with BBR', config: {} },
        { id: 'hysteria2', name: 'Hysteria2 (Brutal)', engine: 'hysteria2', description: 'Hysteria 2 UDP protocol', config: {} }
      ];
      selectPreset(presets[0]);
    }
  }

  function selectPreset(p: ProtocolPreset) {
    selectedPreset = p;
    targetEngine = p.engine;
    generateConfig();
  }

  async function runKeygen() {
    try {
      keygenData = await apiFetch<KeygenResult>('/keygen', {
        method: 'POST',
        body: JSON.stringify({ type: 'x25519' })
      });
      showToast('X25519 Keypair generated', 'success');
      generateConfig();
    } catch (err: any) {
      showToast(err.message || 'Keygen failed', 'error');
    }
  }

  function generateConfig() {
    const configObj = {
      engine: targetEngine,
      preset: selectedPreset?.id || 'custom',
      inbound: {
        port: listenPort,
        sni: sniDomain,
        keys: keygenData ? {
          public_key: keygenData.public_key,
          short_ids: keygenData.short_ids
        } : undefined
      }
    };
    configJson = JSON.stringify(configObj, null, 2);
  }

  async function copyConfig() {
    try {
      await navigator.clipboard.writeText(configJson);
      showToast('JSON config copied to clipboard', 'success');
    } catch (_) {
      showToast('Failed to copy JSON', 'error');
    }
  }

  onMount(() => {
    loadPresets();
  });
</script>

<div class="view-header">
  <h2>Config Studio &amp; Protocol Engine</h2>
  <button class="btn-primary" onclick={runKeygen}>Generate Keypair</button>
</div>

<div class="studio-layout">
  <div class="card preset-sidebar">
    <h3>Presets</h3>
    {#each presets as p}
      <button 
        class="preset-card" 
        class:selected={selectedPreset?.id === p.id}
        onclick={() => selectPreset(p)}
      >
        <strong>{p.name}</strong>
        <span class="desc">{p.description}</span>
        <span class="badge">{p.engine}</span>
      </button>
    {/each}
  </div>

  <div class="card config-editor">
    <h3>Configuration Parameters</h3>
    <div class="form-group">
      <label for="p">Listen Port</label>
      <input id="p" type="number" bind:value={listenPort} oninput={generateConfig} />
    </div>
    <div class="form-group">
      <label for="s">SNI Domain</label>
      <input id="s" type="text" bind:value={sniDomain} oninput={generateConfig} />
    </div>
    {#if keygenData}
      <div class="keygen-box">
        <h4>Generated X25519 Keys</h4>
        <p>Public Key: <code>{keygenData.public_key}</code></p>
        <p>Private Key: <code>{keygenData.private_key}</code></p>
      </div>
    {/if}
  </div>

  <div class="card preview-pane">
    <div class="pane-header">
      <h3>Config Preview</h3>
      <button class="btn-sm" onclick={copyConfig}>Copy JSON</button>
    </div>
    <pre><code>{configJson}</code></pre>
  </div>
</div>

<style>
  .view-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
  .view-header h2 { margin: 0; font-size: 20px; font-weight: 650; }
  .studio-layout { display: grid; grid-template-columns: 260px 300px 1fr; gap: 20px; }
  .card { background: #141A24; border: 1px solid rgba(255,255,255,0.08); border-radius: 14px; padding: 20px; }
  .card h3 { margin: 0 0 16px; font-size: 14px; text-transform: uppercase; color: rgba(255,255,255,0.7); }
  .preset-card {
    display: flex; flex-direction: column; gap: 4px;
    background: #0F1420; border: 1px solid rgba(255,255,255,0.08);
    border-radius: 8px; padding: 12px; margin-bottom: 10px;
    text-align: left; color: #fff; cursor: pointer; position: relative;
  }
  .preset-card.selected, .preset-card:hover { border-color: #FF7A1A; background: rgba(255,122,26,0.1); }
  .desc { font-size: 12px; color: rgba(255,255,255,0.5); }
  .badge { position: absolute; top: 10px; right: 10px; font-size: 10px; background: rgba(255,255,255,0.1); padding: 2px 6px; border-radius: 4px; }
  .form-group { margin-bottom: 14px; }
  .form-group label { display: block; font-size: 12px; color: rgba(255,255,255,0.7); margin-bottom: 6px; }
  input { background: #0F1420; border: 1px solid rgba(255,255,255,0.12); color: #fff; padding: 10px; border-radius: 8px; font: inherit; width: 100%; box-sizing: border-box; }
  .btn-primary { background: #FF7A1A; color: #1a1204; border: none; font-weight: 700; padding: 10px 16px; border-radius: 8px; cursor: pointer; }
  .btn-sm { background: #1A2230; color: #fff; border: 1px solid rgba(255,255,255,0.1); padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; }
  .pane-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
  pre { background: #0F1420; padding: 14px; border-radius: 8px; overflow-x: auto; color: #27D17C; font-family: monospace; font-size: 13px; margin: 0; }
  .keygen-box { background: #0F1420; padding: 12px; border-radius: 8px; font-size: 12px; margin-top: 12px; }
  .keygen-box h4 { margin: 0 0 8px; color: #FF7A1A; }
</style>
