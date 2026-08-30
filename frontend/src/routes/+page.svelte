<script lang="ts">
	import { tr } from '$lib/i18n';
  import { onMount, type Component } from 'svelte';
  import { fade, fly } from 'svelte/transition';
  import { apiFetch, setSession, clearSession, getAuthToken, onSessionExpired } from '$lib/api';
  import { watchIdle } from '$lib/idle';
  import Sidebar from '$lib/components/Sidebar.svelte';
  import { session, canSeeTab } from '$lib/session.svelte';
  import Toast, { showToast } from '$lib/components/Toast.svelte';

  let token = $state(getAuthToken());
  let username = $state('admin');
  let password = $state('');
  let authError = $state('');
  let activeTab = $state('overview');
  let mobileMenuOpen = $state(false);

  // First-run setup (no admin exists yet): the panel prints a one-time token on
  // first boot; the operator creates the owner account here rather than curling.
  let setupRequired = $state(false);
  let setupToken = $state('');
  let confirmPw = $state('');
  let setupError = $state('');

  async function handleSetup(e?: Event) {
    if (e) e.preventDefault();
    setupError = '';
    if (password !== confirmPw) { setupError = tr('app.passwords_do_not_match'); return; }
    try {
      await apiFetch('/setup/init', {
        method: 'POST',
        body: JSON.stringify({ token: setupToken.trim(), username, password, password_confirm: confirmPw }),
      });
      showToast(tr('app.administrator_created'), 'success');
      setupRequired = false;
      await handleLogin();
    } catch (err: any) {
      setupError = err.message || tr('app.setup_failed');
    }
  }

  let CurrentView = $state<Component | null>(null);
  let componentLoading = $state(false);

  const viewLoaders: Record<string, () => Promise<{ default: Component }>> = {
    overview: () => import('$lib/views/OverviewView.svelte'),
    wizard: () => import('$lib/views/SetupWizardView.svelte'),
    inbounds: () => import('$lib/views/InboundsView.svelte'),
    users: () => import('$lib/views/UsersView.svelte'),
    admins: () => import('$lib/views/AdminsView.svelte'),
    routing: () => import('$lib/views/RoutingView.svelte'),
    online: () => import('$lib/views/OnlineView.svelte'),
    usage: () => import('$lib/views/UsageView.svelte'),
    audit: () => import('$lib/views/AuditView.svelte'),
    nodes: () => import('$lib/views/NodesView.svelte'),
    studio: () => import('../routes/studio/StudioView.svelte'),
    domains: () => import('$lib/views/DomainsView.svelte'),
    forgedns: () => import('$lib/views/ForgeDNSView.svelte'),
    edge: () => import('$lib/views/ForgeEdgeView.svelte'),
    certs: () => import('$lib/views/CertificatesView.svelte'),
    system: () => import('$lib/views/SystemHealthView.svelte')
  };

  async function loadTabModule(tab: string) {
    // A tab this role cannot reach is not loaded, whatever asked for it — a
    // remembered tab from a previous session, a link, or a stale navigation
    // state. Falling back to the overview is the one tab every role has.
    if (!canSeeTab(tab, session.role)) tab = 'overview';
    activeTab = tab;
    componentLoading = true;
    try {
      const loader = viewLoaders[tab] || viewLoaders['overview'];
      const mod = await loader();
      CurrentView = mod.default;
    } catch (err: any) {
      showToast(tr('app.failed_to_lazy_load_view'), 'error');
    } finally {
      componentLoading = false;
    }
  }

  async function handleLogin(e?: Event) {
    if (e) e.preventDefault();
    authError = '';
    try {
      // The backend login endpoint is POST /api/login and returns an
      // access+refresh pair (not /api/auth/login and not {token}). This mismatch
      // meant login silently failed and the panel could never be entered.
      const res = await apiFetch<{ access_token: string; refresh_token: string }>('/login', {
        method: 'POST',
        body: JSON.stringify({ username, password })
      });
      // Keep BOTH halves. The refresh token was already being received and
      // thrown away, which is why an expired access token filled the panel with
      // bare 401s that named no cause and offered no way back.
      token = res.access_token;
      setSession(res.access_token, res.refresh_token);
      // Learn WHO signed in before the first view renders. Everything that
      // decides what to offer reads this, and rendering the navigation first
      // would flash the owner's tabs at a reseller.
      await session.load();
      showToast(tr('app.signed_in_successfully'), 'success');
      await loadTabModule('overview');
    } catch (err: any) {
      authError = err.message || tr('app.login_failed');
    }
  }

  function handleLogout() {
    token = '';
    clearSession();
    showToast(tr('app.logged_out'), 'info');
  }

  // An unattended dashboard is full control of every server for whoever walks
  // past it, and refresh tokens mean an idle tab no longer breaks on its own.
  // The warning is shown rather than toasted: a toast disappears, and the whole
  // point is that it is still on screen when someone comes back to the desk.
  let idleWarning = $state(0);

  $effect(() => {
    if (!token) {
      idleWarning = 0;
      return;
    }
    return watchIdle({
      onWarn: (secondsLeft) => { idleWarning = secondsLeft; },
      onResume: () => { idleWarning = 0; },
      onTimeout: () => {
        idleWarning = 0;
        token = '';
        clearSession();
        authError = 'You were signed out after a period of inactivity.';
      }
    });
  });

  // When the refresh finally fails the session is genuinely over. Say so once,
  // and drop to the sign-in screen — rather than letting every in-flight call
  // surface its own unexplained failure.
  onMount(() => onSessionExpired(() => {
    if (!token) return;
    token = '';
    authError = 'Your session expired. Please sign in again.';
    showToast(tr('app.session_expired_please_sign_in_again'), 'info');
  }));

  onMount(async () => {
    if (token) {
      // A restored session goes through the same step a fresh login does. The
      // token in localStorage says nothing about the role it carries.
      await session.load();
      loadTabModule('overview');
      return;
    }
    try {
      const st = await apiFetch<{ setup_required: boolean }>('/setup/status');
      setupRequired = st.setup_required;
    } catch (_) { /* older builds have no setup endpoint */ }
  });
</script>

<svelte:head>
  <title>{tr('app.forgepanel_admin_dashboard')}</title>
</svelte:head>

<Toast />

{#if !token && setupRequired}
  <div class="login-wrapper" in:fade={{ duration: 200 }}>
    <div class="login-card" in:fly={{ y: 24, duration: 300 }}>
      <div class="brand">
        <div class="logo-box"><span class="logo">⚡</span></div>
        <h1>ForgePanel</h1>
      </div>
      <p class="subtitle">{tr('app.first_run_create_your_administrator_account')}</p>

      <form onsubmit={handleSetup} data-testid="setup-form">
        <div class="form-group">
          <label for="stoken">{tr('app.setup_token')}</label>
          <input id="stoken" data-testid="setup-token" type="text" bind:value={setupToken} placeholder={tr('app.printed_on_first_boot')} required />
        </div>
        <div class="form-group">
          <label for="suser">{tr('app.username')}</label>
          <input id="suser" type="text" bind:value={username} placeholder={tr('app.admin')} required />
        </div>
        <div class="form-group">
          <label for="spwd">{tr('app.password')}</label>
          <input id="spwd" type="password" bind:value={password} placeholder="••••••••" required />
        </div>
        <div class="form-group">
          <label for="scpwd">{tr('app.confirm_password')}</label>
          <input id="scpwd" type="password" bind:value={confirmPw} placeholder="••••••••" required />
        </div>
        <button type="submit" class="btn-submit" data-testid="setup-submit">{tr('app.create_administrator')}</button>
      </form>
      {#if setupError}<div class="err-box" in:fade>{setupError}</div>{/if}
    </div>
  </div>
{:else if !token}
  <div class="login-wrapper" in:fade={{ duration: 200 }}>
    <div class="login-card" in:fly={{ y: 24, duration: 300 }}>
      <div class="brand">
        <div class="logo-box">
          <span class="logo">⚡</span>
        </div>
        <h1>ForgePanel</h1>
      </div>
      <p class="subtitle">{tr('app.high_performance_control_plane')}</p>

      <form onsubmit={handleLogin}>
        <div class="form-group">
          <label for="uname">{tr('app.username')}</label>
          <input id="uname" type="text" bind:value={username} placeholder={tr('app.admin')} required />
        </div>
        <div class="form-group">
          <label for="pwd">{tr('app.password')}</label>
          <input id="pwd" type="password" bind:value={password} placeholder="••••••••" required />
        </div>
        <button type="submit" class="btn-submit">{tr('app.sign_in')}</button>
      </form>

      {#if authError}
        <div class="err-box" in:fade>{authError}</div>
      {/if}
    </div>
  </div>
{:else}
  <div class="app-layout" in:fade={{ duration: 150 }}>
    {#if idleWarning > 0}
      <div class="idle-banner" role="alert" data-testid="idle-warning">
        {tr('app.signing_you_out_in_s_no', { idleWarning })}
        <!-- The click itself is the activity: the capture-phase mousedown
             listener rearms the timer and clears this banner through onResume.
             Setting idleWarning to 0 here instead would hide the banner even in
             the case where the timer did NOT rearm, which is the one case where
             the operator most needs to see it. -->
        <button onclick={() => {}}>{tr('app.i_m_still_here')}</button>
      </div>
    {/if}
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
            <span>{tr('app.signed_in_as')} <strong>{tr('app.admin')}</strong></span>
          </div>
        </div>

        <div class="nav-right">
          <button class="logout-btn" onclick={handleLogout}>{tr('app.sign_out')}</button>
        </div>
      </header>

      <main class="page-container">
        {#if componentLoading}
          <div class="loading-state" in:fade={{ duration: 100 }}>
            <div class="spinner"></div>
            <span>{tr('app.lazy_loading_view_module')}</span>
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
  .idle-banner {
    position: fixed;
    top: 0;
    inset-inline-start: 0;
    inset-inline-end: 0;
    z-index: 60;
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 12px;
    padding: 10px 16px;
    background: var(--warn);
    color: var(--card-deep);
    font-size: 13px;
    font-weight: 600;
  }
  .idle-banner button {
    background: var(--shadow);
    color: var(--fg);
    border: 0;
    border-radius: 6px;
    padding: 4px 10px;
    font: inherit;
    cursor: pointer;
  }

  :global(body) {
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", "Segoe UI", Roboto, sans-serif;
    background: var(--bg-deep);
    color: var(--t-1);
    -webkit-font-smoothing: antialiased;
  }

  .login-wrapper {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    padding: 20px;
    box-sizing: border-box;
    background: radial-gradient(circle at center, var(--bg) 0%, var(--bg-deep) 100%);
  }
  .login-card {
    background: var(--card-glass);
    backdrop-filter: blur(16px);
    border: 1px solid var(--ln-3);
    border-radius: 20px;
    padding: 36px;
    width: 100%;
    max-width: 380px;
    box-shadow: 0 24px 60px var(--shadow);
  }
  .brand { display: flex; align-items: center; gap: 12px; justify-content: center; }
  .logo-box {
    width: 40px; height: 40px;
    border-radius: 12px;
    background: linear-gradient(135deg, rgba(255,122,26,0.3) 0%, rgba(255,122,26,0.05) 100%);
    border: 1px solid rgba(255,122,26,0.4);
    display: flex; align-items: center; justify-content: center;
  }
  .brand h1 { margin: 0; font-size: 24px; color: var(--fg); font-weight: 700; letter-spacing: -0.02em; }
  .logo { font-size: 20px; }
  .subtitle { text-align: center; color: var(--t-7); font-size: 13px; margin: 8px 0 28px; }
  .form-group { margin-bottom: 18px; }
  .form-group label { display: block; font-size: 12px; color: var(--t-3); margin-bottom: 6px; font-weight: 500; }
  input {
    width: 100%;
    min-height: 44px;
    padding: 10px 14px;
    background: var(--card-deep);
    border: 1px solid var(--ln-4);
    border-radius: 10px;
    color: var(--fg);
    box-sizing: border-box;
    font-size: 14px;
  }
  input:focus {
    outline: none;
    border-color: var(--acc);
    box-shadow: 0 0 0 3px rgba(255,122,26,0.2);
  }
  .btn-submit {
    width: 100%;
    min-height: 44px;
    background: var(--acc);
    color: var(--acc-soft);
    font-weight: 700;
    border: none;
    border-radius: 10px;
    cursor: pointer;
    font-size: 14px;
    margin-top: 10px;
    transition: transform 0.15s ease, filter 0.15s ease;
  }
  .btn-submit:active { transform: scale(0.98); }
  .err-box { margin-top: 14px; padding: 10px; background: rgba(255,77,77,0.15); color: var(--bad); border-radius: 8px; font-size: 13px; text-align: center; }

  .app-layout { display: flex; min-height: 100vh; }
  .main-content { flex: 1; display: flex; flex-direction: column; min-width: 0; }
  .top-nav {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 16px 24px;
    border-bottom: 1px solid var(--ln-2);
    background: var(--card-deep);
    min-height: 60px;
    box-sizing: border-box;
  }
  .nav-left { display: flex; align-items: center; gap: 14px; }
  .mobile-toggle {
    display: none;
    background: var(--ln-1);
    border: 1px solid var(--ln-4);
    color: var(--fg);
    font-size: 18px;
    padding: 6px 12px;
    border-radius: 8px;
    cursor: pointer;
    min-height: 40px;
  }
  .user-badge { display: flex; align-items: center; gap: 8px; font-size: 13px; color: var(--t-3); }
  .online-indicator { width: 6px; height: 6px; border-radius: 50%; background: var(--ok); }
  .logout-btn {
    background: var(--ln-1);
    border: 1px solid var(--ln-3);
    color: var(--t-2);
    padding: 8px 16px;
    border-radius: 8px;
    font-size: 13px;
    cursor: pointer;
    font-weight: 500;
  }
  .logout-btn:hover { background: rgba(255,77,77,0.15); color: var(--bad); border-color: rgba(255,77,77,0.3); }

  .page-container { flex: 1; padding: 28px; max-width: 1200px; box-sizing: border-box; }
  .loading-state { display: flex; align-items: center; gap: 12px; color: var(--t-5); padding: 40px; }
  .spinner {
    width: 20px; height: 20px;
    border: 2px solid rgba(255,122,26,0.3);
    border-top-color: var(--acc);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  @media (max-width: 768px) {
    .mobile-toggle { display: block; }
    .page-container { padding: 16px; }
  }
</style>
