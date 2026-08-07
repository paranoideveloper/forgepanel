<script lang="ts">
  import { onMount } from 'svelte';
  import { apiFetch, setAuthToken, getAuthToken } from '$lib/api';
  import type { DNSZone, DNSAdapter } from '$lib/types';

  let token = $state(getAuthToken());
  let username = $state('admin');
  let password = $state('');
  let loginErr = $state('');

  let adapters = $state<DNSAdapter[]>([]);
  let zones = $state<DNSZone[]>([]);
  let selectedZone = $state<DNSZone | null>(null);

  let newDomain = $state('');
  let selectedAdapter = $state('');
  let createErr = $state('');
  let copyMsg = $state('');

  async function handleLogin(e?: Event) {
    if (e) e.preventDefault();
    loginErr = '';
    try {
      const res = await apiFetch<{ access_token: string }>('/login', {
        method: 'POST',
        body: JSON.stringify({ username, password })
      });
      token = res.access_token;
      setAuthToken(token);
      await loadData();
    } catch (err: any) {
      loginErr = err.message || 'Login failed';
    }
  }

  async function loadData() {
    try {
      adapters = await apiFetch<DNSAdapter[]>('/admin/forgedns/adapters');
      if (adapters.length > 0 && !selectedAdapter) {
        selectedAdapter = adapters[0].id;
      }
      zones = await apiFetch<DNSZone[]>('/admin/forgedns/zones');
    } catch (err: any) {
      if (err.status === 401) {
        token = '';
        setAuthToken('');
      }
    }
  }

  async function createZone() {
    createErr = '';
    if (!newDomain.trim()) {
      createErr = 'Domain is required';
      return;
    }
    try {
      const newZone = await apiFetch<DNSZone>('/admin/forgedns/zones', {
        method: 'POST',
        body: JSON.stringify({ domain: newDomain.trim(), adapter: selectedAdapter })
      });
      newDomain = '';
      selectedZone = newZone;
      await loadData();
    } catch (err: any) {
      createErr = err.message || 'Failed to create zone';
    }
  }

  async function deleteZone(id: number) {
    if (!confirm('Are you sure you want to delete this DNS tunnel zone?')) return;
    try {
      await apiFetch(`/admin/forgedns/zones/${id}`, { method: 'DELETE' });
      if (selectedZone?.id === id) selectedZone = null;
      await loadData();
    } catch (err: any) {
      alert(err.message || 'Failed to delete zone');
    }
  }

  function selectZone(zone: DNSZone) {
    selectedZone = zone;
  }

  async function copyUri(uri: string) {
    try {
      await navigator.clipboard.writeText(uri);
      copyMsg = 'Copied!';
      setTimeout(() => (copyMsg = ''), 2000);
    } catch (_) {
      copyMsg = 'Copy failed';
    }
  }

  onMount(() => {
    if (token) {
      loadData();
    }
  });
</script>

<svelte:head>
  <title>ForgePanel — DNS Tunnels</title>
</svelte:head>

<header>
  <div class="dot {token ? 'on' : ''}"></div>
  <h1>ForgePanel — DNS Tunnels</h1>
</header>

<main>
  {#if !token}
    <div class="card auth-card">
      <h2>Sign in</h2>
      <form onsubmit={handleLogin}>
        <div class="row">
          <input type="text" bind:value={username} placeholder="Username" required />
          <input type="password" bind:value={password} placeholder="Password" required />
        </div>
        <div class="row" style="margin-top:12px">
          <button type="submit">Sign in</button>
        </div>
      </form>
      {#if loginErr}
        <div class="err">{loginErr}</div>
      {/if}
    </div>
  {:else}
    <div class="card">
      <h2>Create a DNS tunnel — no terminal needed</h2>
      <div class="row">
        <input type="text" bind:value={newDomain} placeholder="tunnel domain, e.g. t.example.com" style="flex:1;min-width:220px" />
        <select bind:value={selectedAdapter}>
          {#each adapters as ad}
            <option value={ad.id}>{ad.name}</option>
          {/each}
        </select>
        <button onclick={createZone}>Create &amp; activate</button>
      </div>
      <div class="muted" style="margin-top:8px;font-size:13px">
        Pick a wire format, enter your delegated domain, and click. The panel starts the authoritative DNS listener for you.
      </div>
      {#if createErr}
        <div class="err">{createErr}</div>
      {/if}
    </div>

    <div class="card">
      <h2>Tunnel zones</h2>
      {#if zones.length === 0}
        <p class="muted">No tunnel zones configured yet.</p>
      {:else}
        <table>
          <thead>
            <tr>
              <th>Zone</th>
              <th>Adapter</th>
              <th>Status</th>
              <th>Sessions</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {#each zones as z}
              <tr>
                <td><strong>{z.domain}</strong></td>
                <td><code>{z.adapter}</code></td>
                <td>
                  <span class="pill {z.active ? 'on' : 'off'}">
                    {z.active ? 'Active' : 'Stopped'}
                  </span>
                </td>
                <td>{z.sessions || 0}</td>
                <td>
                  <button class="ghost" onclick={() => selectZone(z)}>Setup</button>
                  <button class="ghost danger" onclick={() => deleteZone(z.id)}>Delete</button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </div>

    {#if selectedZone}
      <div class="card">
        <h2>Setup — {selectedZone.domain}</h2>
        <p class="muted" style="font-size:13px">
          Add these DNS records at your registrar to delegate the zone to this server, then import the client URI.
        </p>
        {#if selectedZone.ns_records && selectedZone.ns_records.length > 0}
          <table>
            <thead>
              <tr><th>Host</th><th>Target</th></tr>
            </thead>
            <tbody>
              {#each selectedZone.ns_records as ns}
                <tr>
                  <td><code>{ns.host}</code></td>
                  <td><code>{ns.target}</code></td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}
        {#if selectedZone.client_uri}
          <p style="margin-top:14px">
            Client URI: <code>{selectedZone.client_uri}</code>
            <button class="ghost" onclick={() => copyUri(selectedZone!.client_uri)}>Copy</button>
            {#if copyMsg}<span class="copy-hint">{copyMsg}</span>{/if}
          </p>
        {/if}
      </div>
    {/if}
  {/if}
</main>

<style>
  :global(:root) {
    --bg: #0B0F16;
    --panel: #141A24;
    --line: rgba(255, 255, 255, .08);
    --text: rgba(255, 255, 255, .92);
    --muted: rgba(255, 255, 255, .70);
    --accent: #FF7A1A;
    --ok: #27D17C;
    --bad: #FF4D4D;
  }
  :global(body) {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font: 15px/1.5 system-ui, Segoe UI, Roboto, sans-serif;
  }
  header {
    padding: 18px 24px;
    background: linear-gradient(90deg, #111a2b, #0b0f17);
    border-bottom: 1px solid var(--line);
    display: flex;
    align-items: center;
    gap: 12px;
  }
  header h1 {
    font-size: 18px;
    margin: 0;
    font-weight: 650;
  }
  header .dot {
    width: 9px;
    height: 9px;
    border-radius: 50%;
    background: var(--bad);
  }
  header .dot.on {
    background: var(--ok);
  }
  main {
    max-width: 980px;
    margin: 0 auto;
    padding: 24px;
  }
  .card {
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: 14px;
    padding: 20px;
    margin-bottom: 20px;
  }
  h2 {
    font-size: 15px;
    margin: 0 0 14px;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: .06em;
  }
  input, select, button {
    font: inherit;
    border-radius: 9px;
    border: 1px solid var(--line);
    background: #0e1420;
    color: var(--text);
    padding: 9px 12px;
  }
  button {
    background: var(--accent);
    border: 0;
    color: #1a1204;
    cursor: pointer;
    font-weight: 700;
  }
  button.ghost {
    background: #1A2230;
    color: var(--text);
  }
  button.danger {
    color: var(--bad);
  }
  button:hover {
    filter: brightness(1.08);
  }
  .row {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    align-items: center;
  }
  table {
    width: 100%;
    border-collapse: collapse;
  }
  th, td {
    text-align: left;
    padding: 10px 8px;
    border-bottom: 1px solid var(--line);
    font-size: 14px;
  }
  th {
    color: var(--muted);
    font-weight: 600;
  }
  code {
    background: #0e1420;
    padding: 2px 6px;
    border-radius: 6px;
    font-size: 13px;
  }
  .pill {
    display: inline-block;
    padding: 2px 9px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 600;
  }
  .pill.on {
    background: rgba(51, 196, 129, .16);
    color: var(--ok);
  }
  .pill.off {
    background: rgba(255, 92, 108, .16);
    color: var(--bad);
  }
  .err {
    color: var(--bad);
    margin-top: 10px;
    font-size: 13px;
  }
  .muted {
    color: var(--muted);
  }
  .copy-hint {
    margin-left: 8px;
    font-size: 12px;
    color: var(--ok);
  }
</style>
