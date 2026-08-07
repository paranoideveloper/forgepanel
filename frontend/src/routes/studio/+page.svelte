<script lang="ts">
  import { onMount } from 'svelte';
  import { apiFetch } from '$lib/api';

  interface ProtocolPreset {
    id: string;
    name: string;
    engine: string;
    description: string;
  }

  let presets = $state<ProtocolPreset[]>([]);
  let selectedPreset = $state<ProtocolPreset | null>(null);
  let configJson = $state<string>('');
  let validationMsg = $state<{ type: 'ok' | 'err'; text: string } | null>(null);

  let listenPort = $state<number>(443);
  let domain = $state<string>('example.com');
  let selectedEngine = $state<string>('xray');

  async function loadPresets() {
    try {
      presets = await apiFetch<ProtocolPreset[]>('/protocols/presets');
      if (presets.length > 0) {
        selectPreset(presets[0]);
      }
    } catch (_) {
      // Fallback presets if offline
      presets = [
        { id: 'vless-reality', name: 'VLESS Reality (Xray)', engine: 'xray', description: 'VLESS + Vision + REALITY TLS' },
        { id: 'tuic-v5', name: 'TUIC v5 (Native)', engine: 'tuic', description: 'TUIC over QUIC with BBR' },
        { id: 'hysteria2', name: 'Hysteria2 (Brutal)', engine: 'hysteria2', description: 'Hysteria 2 UDP protocol' }
      ];
      selectPreset(presets[0]);
    }
  }

  function selectPreset(preset: ProtocolPreset) {
    selectedPreset = preset;
    selectedEngine = preset.engine;
    generatePreview();
  }

  async function generatePreview() {
    validationMsg = null;
    const sampleConfig = {
      engine: selectedEngine,
      inbound: {
        protocol: selectedPreset?.id || 'vless',
        port: listenPort,
        settings: {
          domain,
          tls: 'reality'
        }
      }
    };
    configJson = JSON.stringify(sampleConfig, null, 2);
  }

  function validateConfig() {
    try {
      JSON.parse(configJson);
      validationMsg = { type: 'ok', text: 'JSON config syntax is valid.' };
    } catch (err: any) {
      validationMsg = { type: 'err', text: `Syntax Error: ${err.message}` };
    }
  }

  onMount(() => {
    loadPresets();
  });
</script>

<svelte:head>
  <title>ForgePanel — Config Studio</title>
</svelte:head>

<div class="studio-container">
  <header class="studio-header">
    <h1>Config Studio</h1>
    <p>Protocol engine testing, preset builder & live JSON preview</p>
  </header>

  <div class="studio-grid">
    <div class="panel-card sidebar-presets">
      <h3>Protocol Presets</h3>
      <div class="preset-list">
        {#each presets as p}
          <button 
            class="preset-item" 
            class:selected={selectedPreset?.id === p.id}
            onclick={() => selectPreset(p)}
          >
            <div class="preset-title">{p.name}</div>
            <div class="preset-desc">{p.description}</div>
            <span class="engine-badge">{p.engine}</span>
          </button>
        {/each}
      </div>
    </div>

    <div class="panel-card config-form">
      <h3>Configuration Options</h3>
      <div class="form-row">
        <label for="port">Listen Port</label>
        <input id="port" type="number" bind:value={listenPort} oninput={generatePreview} />
      </div>
      <div class="form-row">
        <label for="dom">SNI Domain / ServerName</label>
        <input id="dom" type="text" bind:value={domain} oninput={generatePreview} />
      </div>
      <div class="form-row">
        <label for="eng">Core Engine</label>
        <select id="eng" bind:value={selectedEngine} onchange={generatePreview}>
          <option value="xray">Xray-core</option>
          <option value="tuic">TUIC v5</option>
          <option value="hysteria2">Hysteria2</option>
          <option value="sing-box">Sing-box</option>
        </select>
      </div>

      <button class="btn-validate" onclick={validateConfig}>Validate JSON</button>

      {#if validationMsg}
        <div class="msg-box {validationMsg.type}">
          {validationMsg.text}
        </div>
      {/if}
    </div>

    <div class="panel-card json-preview">
      <h3>Generated Config JSON</h3>
      <pre><code>{configJson}</code></pre>
    </div>
  </div>
</div>

<style>
  :global(body) {
    margin: 0;
    font-family: system-ui, -apple-system, sans-serif;
    background: #0B0F16;
    color: rgba(255,255,255,0.92);
  }
  .studio-container { max-width: 1200px; margin: 0 auto; padding: 24px; }
  .studio-header { margin-bottom: 24px; }
  .studio-header h1 { margin: 0; font-size: 24px; color: #FF7A1A; }
  .studio-header p { margin: 4px 0 0; color: rgba(255,255,255,0.6); font-size: 14px; }
  .studio-grid { display: grid; grid-template-columns: 280px 320px 1fr; gap: 20px; }
  .panel-card {
    background: #141A24;
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 12px;
    padding: 20px;
  }
  .panel-card h3 { margin: 0 0 16px; font-size: 14px; text-transform: uppercase; color: rgba(255,255,255,0.7); }
  .preset-list { display: flex; flex-direction: column; gap: 10px; }
  .preset-item {
    background: #0F1420;
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 8px;
    padding: 12px;
    text-align: left;
    cursor: pointer;
    color: #fff;
    position: relative;
  }
  .preset-item.selected, .preset-item:hover {
    border-color: #FF7A1A;
    background: rgba(255,122,26,0.1);
  }
  .preset-title { font-weight: 600; font-size: 14px; margin-bottom: 4px; }
  .preset-desc { font-size: 12px; color: rgba(255,255,255,0.6); }
  .engine-badge {
    position: absolute;
    top: 10px;
    right: 10px;
    font-size: 10px;
    background: rgba(255,255,255,0.1);
    padding: 2px 6px;
    border-radius: 4px;
    text-transform: uppercase;
  }
  .form-row { margin-bottom: 16px; }
  .form-row label { display: block; font-size: 12px; color: rgba(255,255,255,0.7); margin-bottom: 6px; }
  input, select {
    width: 100%;
    padding: 8px 12px;
    background: #0F1420;
    border: 1px solid rgba(255,255,255,0.12);
    border-radius: 6px;
    color: #fff;
    box-sizing: border-box;
  }
  .btn-validate {
    width: 100%;
    background: #FF7A1A;
    color: #1a1204;
    font-weight: 700;
    border: none;
    padding: 10px;
    border-radius: 8px;
    cursor: pointer;
    margin-top: 12px;
  }
  .json-preview pre {
    background: #0B0F16;
    padding: 16px;
    border-radius: 8px;
    overflow-x: auto;
    font-family: monospace;
    font-size: 13px;
    color: #27D17C;
  }
  .msg-box {
    margin-top: 12px;
    padding: 10px;
    border-radius: 6px;
    font-size: 12px;
  }
  .msg-box.ok { background: rgba(39,209,124,0.15); color: #27D17C; border: 1px solid #27D17C; }
  .msg-box.err { background: rgba(255,77,77,0.15); color: #FF4D4D; border: 1px solid #FF4D4D; }
</style>
