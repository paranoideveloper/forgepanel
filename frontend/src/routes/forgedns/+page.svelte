<script lang="ts">
	import { tr } from '$lib/i18n';
  import { apiFetch, setSession, clearSession, getAuthToken, onSessionExpired } from '$lib/api';
  import ForgeDNSView from '$lib/views/ForgeDNSView.svelte';

  let token = $state(getAuthToken());
  let username = $state('admin');
  let password = $state('');
  let loginErr = $state('');

  async function handleLogin(e?: Event) {
    if (e) e.preventDefault();
    loginErr = '';
    try {
      // Keep BOTH halves. Storing only the access token is why an expired
      // session used to fill the panel with bare 401s and no way back.
      const res = await apiFetch<{ access_token: string; refresh_token?: string }>('/login', {
        method: 'POST',
        body: JSON.stringify({ username, password })
      });
      token = res.access_token;
      setSession(res.access_token, res.refresh_token);
    } catch (err: any) {
      loginErr = err.message || tr('forgedns.login_failed');
    }
  }

  function signOut() {
    token = '';
    clearSession();
  }
</script>

<svelte:head>
  <title>{tr('forgedns.forgepanel_dns_tunnels')}</title>
</svelte:head>

<header>
  <div class="dot {token ? 'on' : ''}"></div>
  <h1>{tr('forgedns.forgepanel_dns_tunnels')}</h1>
  {#if token}<button class="ghost signout" onclick={signOut}>{tr('forgedns.sign_out')}</button>{/if}
</header>

<main>
  {#if !token}
    <div class="card auth-card">
      <h2>{tr('forgedns.sign_in')}</h2>
      <form onsubmit={handleLogin}>
        <div class="row">
          <input type="text" bind:value={username} placeholder={tr('forgedns.username')} required />
          <input type="password" bind:value={password} placeholder={tr('forgedns.password')} required />
        </div>
        <div class="row" style="margin-top:12px">
          <button type="submit">{tr('forgedns.sign_in')}</button>
        </div>
      </form>
      {#if loginErr}
        <div class="err">{loginErr}</div>
      {/if}
    </div>
  {:else}
    <!-- Reuse the shared, tested zone-management UI so this standalone entry and
         the admin panel can never drift apart again. -->
    <ForgeDNSView />
  {/if}
</main>

<style>
  :global(:root) {
    --bg: var(--bg-deep);
    --panel: var(--card);
    --line: var(--ln-3);
    --text: var(--ln-5);
    --muted: var(--ln-5);
    --accent: var(--acc);
    --ok: var(--ok);
    --bad: var(--bad);
  }
  :global(body) {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font: 15px/1.5 system-ui, Segoe UI, Roboto, sans-serif;
  }
  header {
    padding: 18px 24px;
    background: linear-gradient(90deg, var(--card), var(--bg));
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
  header .signout {
    margin-inline-start: auto;
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
  input, button {
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
    color: var(--acc-soft);
    cursor: pointer;
    font-weight: 700;
  }
  button.ghost {
    background: var(--raised);
    color: var(--text);
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
  .err {
    color: var(--bad);
    margin-top: 10px;
    font-size: 13px;
  }
</style>
