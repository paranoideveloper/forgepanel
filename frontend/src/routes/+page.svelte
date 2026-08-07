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
  let mobileMenuOpen = $state(false);

  let CurrentView = $state<Component | null>(null);
  let componentLoading = $state(false);

  const viewLoaders: Record<string, () => Promise<{ default: Component }>> = {
    overview: () => import('$lib/views/OverviewView.svelte'),
    users: () => import('$lib/views/UsersView.svelte'),
    nodes: () => import('$lib/views/NodesView.svelte'),
    studio: () => import('../routes/studio/StudioView.svelte'),
    domains: () => import('$lib/views/DomainsView.svelte'),
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
    <div class="login-card" in:fly={{ y: 24, duration: 300 }}>
      <div class="brand">
        <div class="logo-box">
          <span class="logo">⚡</span>
        </div>
        <h1>ForgePanel</h1>
      </div>
      <p class="subtitle">High-performance control plane</p>

      <form onsubmit={handleLogin}>
        <div class="form-group">
          <label for="uname">Username</label>
          <input id="uname" type="text" bind:value={username} placeholder="admin" required />
        </div>
        <div class="form-group">
          <label for="pwd">Password</label>
          <input id="pwd" type="password" bind:value={password} placeholder="••••••••" required />
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
    <Sidebar 
      {activeTab} 
      bind:mobileOpen={mobileMenuOpen}
      onTabChange={(tab) => loadTabModule(tab)} 
    />

    <div class="main-content">
      <header class="top-nav">
        <div class="nav-left">
          <button class="mobile-toggle" onclick={() => mobileMenuOpen = !mobileMenuOpen}>
            ☰
          </button>
          <div class="user-badge">
            <span class="online-indicator"></span>
            <span>Signed in as <strong>admin</strong></span>
          </div>
        </div>

        <div class="nav-right">
          <button class="logout-btn" onclick={handleLogout}>Sign Out</button>
        </div>
      </header>

      <main class="page-container">
        {#if componentLoading}
          <div class="loading-state" in:fade={{ duration: 100 }}>
            <div class="spinner"></div>
            <span>Lazy loading view module...</span>
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
    font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", "Segoe UI", Roboto, sans-serif;
    background: #090D16;
    color: rgba(255, 255, 255, 0.92);
    -webkit-font-smoothing: antialiased;
  }

  .login-wrapper {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    padding: 20px;
    box-sizing: border-box;
    background: radial-gradient(circle at center, #111827 0%, #070A10 100%);
  }
  .login-card {
    background: rgba(20, 26, 36, 0.85);
    backdrop-filter: blur(16px);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 20px;
    padding: 36px;
    width: 100%;
    max-width: 380px;
    box-shadow: 0 24px 60px rgba(0, 0, 0, 0.6);
  }
  .brand { display: flex; align-items: center; gap: 12px; justify-content: center; }
  .logo-box {
    width: 40px; height: 40px;
    border-radius: 12px;
    background: linear-gradient(135deg, rgba(255,122,26,0.3) 0%, rgba(255,122,26,0.05) 100%);
    border: 1px solid rgba(255,122,26,0.4);
    display: flex; align-items: center; justify-content: center;
  }
  .brand h1 { margin: 0; font-size: 24px; color: #fff; font-weight: 700; letter-spacing: -0.02em; }
  .logo { font-size: 20px; }
  .subtitle { text-align: center; color: rgba(255,255,255,0.5); font-size: 13px; margin: 8px 0 28px; }
  .form-group { margin-bottom: 18px; }
  .form-group label { display: block; font-size: 12px; color: rgba(255,255,255,0.7); margin-bottom: 6px; font-weight: 500; }
  input {
    width: 100%;
    min-height: 44px;
    padding: 10px 14px;
    background: #0D121F;
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 10px;
    color: #fff;
    box-sizing: border-box;
    font-size: 14px;
  }
  input:focus {
    outline: none;
    border-color: #FF7A1A;
    box-shadow: 0 0 0 3px rgba(255,122,26,0.2);
  }
  .btn-submit {
    width: 100%;
    min-height: 44px;
    background: #FF7A1A;
    color: #1a1204;
    font-weight: 700;
    border: none;
    border-radius: 10px;
    cursor: pointer;
    font-size: 14px;
    margin-top: 10px;
    transition: transform 0.15s ease, filter 0.15s ease;
  }
  .btn-submit:active { transform: scale(0.98); }
  .err-box { margin-top: 14px; padding: 10px; background: rgba(255,77,77,0.15); color: #FF4D4D; border-radius: 8px; font-size: 13px; text-align: center; }

  .app-layout { display: flex; min-height: 100vh; }
  .main-content { flex: 1; display: flex; flex-direction: column; min-width: 0; }
  .top-nav {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 16px 24px;
    border-bottom: 1px solid rgba(255,255,255,0.06);
    background: #0D121F;
    min-height: 60px;
    box-sizing: border-box;
  }
  .nav-left { display: flex; align-items: center; gap: 14px; }
  .mobile-toggle {
    display: none;
    background: rgba(255,255,255,0.05);
    border: 1px solid rgba(255,255,255,0.1);
    color: #fff;
    font-size: 18px;
    padding: 6px 12px;
    border-radius: 8px;
    cursor: pointer;
    min-height: 40px;
  }
  .user-badge { display: flex; align-items: center; gap: 8px; font-size: 13px; color: rgba(255,255,255,0.7); }
  .online-indicator { width: 6px; height: 6px; border-radius: 50%; background: #27D17C; }
  .logout-btn {
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(255,255,255,0.08);
    color: rgba(255,255,255,0.8);
    padding: 8px 16px;
    border-radius: 8px;
    font-size: 13px;
    cursor: pointer;
    font-weight: 500;
  }
  .logout-btn:hover { background: rgba(255,77,77,0.15); color: #FF4D4D; border-color: rgba(255,77,77,0.3); }

  .page-container { flex: 1; padding: 28px; max-width: 1200px; box-sizing: border-box; }
  .loading-state { display: flex; align-items: center; gap: 12px; color: rgba(255,255,255,0.6); padding: 40px; }
  .spinner {
    width: 20px; height: 20px;
    border: 2px solid rgba(255,122,26,0.3);
    border-top-color: #FF7A1A;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  @media (max-width: 768px) {
    .mobile-toggle { display: block; }
    .page-container { padding: 16px; }
  }
</style>
