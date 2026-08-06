<script lang="ts">
  import { onMount, type Component } from 'svelte';
  import { fade, fly } from 'svelte/transition';
  import { apiFetch, setAuthToken, getAuthToken } from '$lib/api';
  import Sidebar from '$lib/components/Sidebar.svelte';
  import Toast, { showToast } from '$lib/components/Toast.svelte';

  let token = $state(getAuthToken());
  let username = $state('admin');
  let password = $state('');
  let authError = $state('');
  let activeTab = $state('overview');

  let CurrentView = $state<Component | null>(null);
  let componentLoading = $state(false);

  const viewLoaders: Record<string, () => Promise<{ default: Component }>> = {
    overview: () => import('$lib/views/OverviewView.svelte'),
    users: () => import('$lib/views/UsersView.svelte'),
    nodes: () => import('$lib/views/NodesView.svelte'),
    studio: () => import('../routes/studio/StudioView.svelte'),
    forgedns: () => import('$lib/views/ForgeDNSView.svelte'),
    certs: () => import('$lib/views/CertificatesView.svelte'),
    system: () => import('$lib/views/SystemHealthView.svelte')
  };

  async function loadTabModule(tab: string) {
    activeTab = tab;
    componentLoading = true;
    try {
      const loader = viewLoaders[tab] || viewLoaders['overview'];
      const mod = await loader();
      CurrentView = mod.default;
    } catch (err: any) {
      showToast('Failed to lazy load view', 'error');
    } finally {
      componentLoading = false;
    }
  }

  async function handleLogin(e?: Event) {
    if (e) e.preventDefault();
    authError = '';
    try {
      const res = await apiFetch<{ token: string }>('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username, password })
      });
      token = res.token;
      setAuthToken(token);
      showToast('Signed in successfully', 'success');
      await loadTabModule('overview');
    } catch (err: any) {
      authError = err.message || 'Login failed';
    }
  }

  function handleLogout() {
    token = '';
    setAuthToken('');
    showToast('Logged out', 'info');
  }

  onMount(() => {
    if (token) {
      loadTabModule('overview');
    }
  });
</script>

<svelte:head>
  <title>ForgePanel Admin Dashboard</title>
</svelte:head>

<Toast />

{#if !token}
  <div class="login-wrapper" in:fade={{ duration: 200 }}>
    <div class="login-card" in:fly={{ y: 20, duration: 250 }}>
      <div class="brand">
        <span class="logo">⚡</span>
        <h1>ForgePanel</h1>
      </div>
      <p class="subtitle">High-performance control plane</p>

      <form onsubmit={handleLogin}>
        <div class="form-group">
          <label for="uname">Username</label>
          <input id="uname" type="text" bind:value={username} required />
        </div>
        <div class="form-group">
          <label for="pwd">Password</label>
          <input id="pwd" type="password" bind:value={password} required />
        </div>
        <button type="submit" class="btn-submit">Sign In</button>
      </form>

      {#if authError}
        <div class="err-box" in:fade>{authError}</div>
      {/if}
    </div>
  </div>
{:else}
  <div class="app-layout" in:fade={{ duration: 150 }}>
    <Sidebar {activeTab} onTabChange={(tab) => loadTabModule(tab)} />

    <div class="main-content">
      <header class="top-nav">
        <div class="user-badge">
          <span>Logged in as <strong>admin</strong></span>
        </div>
        <button class="logout-btn" onclick={handleLogout}>Sign Out</button>
      </header>

      <main class="page-container">
        {#if componentLoading}
          <div class="loading-state" in:fade={{ duration: 100 }}>
            <div class="spinner"></div>
            <span>Lazy loading module...</span>
          </div>
        {:else if CurrentView}
          <div class="view-wrapper" in:fade={{ duration: 180 }}>
            <CurrentView />
          </div>
        {/if}
      </main>
    </div>
  </div>
{/if}

<style>
  :global(body) {
    margin: 0;
    font-family: system-ui, -apple-system, sans-serif;
    background: #0B0F16;
    color: rgba(255, 255, 255, 0.92);
  }
  .login-wrapper {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    background: radial-gradient(circle at center, #111827 0%, #0B0F16 100%);
  }
  .login-card {
    background: #141A24;
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 16px;
    padding: 36px;
    width: 100%;
    max-width: 380px;
    box-shadow: 0 20px 40px rgba(0, 0, 0, 0.5);
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 10px;
    justify-content: center;
  }
  .brand h1 {
    margin: 0;
    font-size: 22px;
    color: #FF7A1A;
  }
  .logo { font-size: 24px; }
  .subtitle { text-align: center; color: rgba(255,255,255,0.5); font-size: 13px; margin: 6px 0 24px; }
  .form-group { margin-bottom: 16px; }
  .form-group label { display: block; font-size: 12px; color: rgba(255,255,255,0.7); margin-bottom: 6px; }
  input {
    width: 100%;
    padding: 10px 12px;
    background: #0F1420;
    border: 1px solid rgba(255, 255, 255, 0.12);
    border-radius: 8px;
    color: #fff;
    box-sizing: border-box;
  }
  .btn-submit {
    width: 100%;
    background: #FF7A1A;
    color: #1a1204;
    font-weight: 700;
    border: none;
    padding: 12px;
    border-radius: 8px;
    cursor: pointer;
    margin-top: 10px;
  }
  .err-box { margin-top: 14px; padding: 10px; background: rgba(255,77,77,0.15); color: #FF4D4D; border-radius: 6px; font-size: 13px; text-align: center; }
  
  .app-layout { display: flex; min-height: 100vh; }
  .main-content { flex: 1; display: flex; flex-direction: column; }
  .top-nav {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 16px 32px;
    border-bottom: 1px solid rgba(255,255,255,0.08);
    background: #0F1420;
  }
  .user-badge { font-size: 13px; color: rgba(255,255,255,0.7); }
  .logout-btn {
    background: rgba(255,255,255,0.05);
    border: 1px solid rgba(255,255,255,0.1);
    color: rgba(255,255,255,0.8);
    padding: 6px 14px;
    border-radius: 6px;
    font-size: 12px;
    cursor: pointer;
  }
  .page-container { flex: 1; padding: 32px; max-width: 1200px; }
  .loading-state { display: flex; align-items: center; gap: 12px; color: rgba(255,255,255,0.6); padding: 40px; }
  .spinner {
    width: 20px; height: 20px;
    border: 2px solid rgba(255,122,26,0.3);
    border-top-color: #FF7A1A;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
