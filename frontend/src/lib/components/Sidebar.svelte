<script lang="ts">
	import { tr, locale, setLocale, locales } from '$lib/i18n';
  import { onMount } from 'svelte';
  import { apiFetch } from '$lib/api';

  // Read from GET /api/version rather than a literal. It was pinned at v1.10.0
  // while the product shipped v1.20.0 — a badge that is confidently wrong is
  // worse than none, because a bug report quotes it.
  let panelVersion = $state('');
  onMount(async () => {
    try {
      const v = await apiFetch<{ version?: string }>('/version');
      if (v?.version) panelVersion = v.version.startsWith('v') ? v.version : 'v' + v.version;
    } catch (_) {
      // A version we could not read is left blank; guessing one is how a wrong
      // number ends up in a bug report.
    }
  });
  import { fly, fade } from 'svelte/transition';

  let { activeTab, mobileOpen = $bindable(false), onTabChange } = $props<{
    activeTab: string;
    mobileOpen?: boolean;
    onTabChange: (tab: string) => void;
  }>();

  // labelKey, not label. A `const tabs` holding tr('...') results would be
  // evaluated once at module init and keep the language it was built in —
  // switching locale would leave the whole navigation in the old one. Storing
  // the key and translating at render time is what makes the switch live.
  const tabs = [
    { id: 'overview', labelKey: 'sidebar.tab.overview', icon: '📊' },
    { id: 'wizard', labelKey: 'sidebar.tab.wizard', icon: '✨' },
    { id: 'inbounds', labelKey: 'sidebar.tab.inbounds', icon: '🔌' },
    { id: 'users', labelKey: 'sidebar.tab.users', icon: '👥' },
    { id: 'admins', labelKey: 'sidebar.tab.admins', icon: '🛡️' },
    { id: 'routing', labelKey: 'sidebar.tab.routing', icon: '🧭' },
    { id: 'online', labelKey: 'sidebar.tab.online', icon: '🟢' },
    { id: 'usage', labelKey: 'sidebar.tab.usage', icon: '📈' },
    { id: 'audit', labelKey: 'sidebar.tab.audit', icon: '📜' },
    { id: 'nodes', labelKey: 'sidebar.tab.nodes', icon: '🌐' },
    { id: 'studio', labelKey: 'sidebar.tab.studio', icon: '⚙️' },
    { id: 'domains', labelKey: 'sidebar.tab.domains', icon: '🌍' },
    { id: 'forgedns', labelKey: 'sidebar.tab.forgedns', icon: '🛰️' },
    { id: 'edge', labelKey: 'sidebar.tab.edge', icon: '☁️' },
    { id: 'certs', labelKey: 'sidebar.tab.certs', icon: '🔒' },
    { id: 'system', labelKey: 'sidebar.tab.system', icon: '🛠️' }
  ];

  function handleSelect(tab: string) {
    onTabChange(tab);
    mobileOpen = false;
  }

  function closeFromBackdrop(event: MouseEvent) {
    if (event.target === event.currentTarget) {
      mobileOpen = false;
    }
  }
</script>

<!-- Desktop Sidebar -->
<aside class="sidebar desktop-only">
  <div class="brand">
    <div class="logo-box">
      <span class="logo">⚡</span>
    </div>
    <div class="brand-text">
      <h2>ForgePanel</h2>
      <span class="version-tag" data-testid="version">{panelVersion}</span>
    </div>
  </div>

  <nav>
    {#each tabs as tab}
      <button 
        class="nav-btn" 
        class:active={activeTab === tab.id}
        onclick={() => handleSelect(tab.id)}
      >
        <span class="icon">{tab.icon}</span>
        <span class="label">{tr(tab.labelKey)}</span>
      </button>
    {/each}
  </nav>

  <div class="sidebar-footer">
    <div class="lang-switch" role="group" aria-label={tr('sidebar.language')}>
      {#each locales as l}
        <button
          class="lang-btn"
          class:active={locale() === l.code}
          lang={l.code}
          aria-pressed={locale() === l.code}
          onclick={() => setLocale(l.code)}
        >{l.nativeName}</button>
      {/each}
    </div>
    <div class="status-pulse">
      <span class="pulse-dot"></span>
      <span>{tr('sidebar.control_plane_online')}</span>
    </div>
  </div>
</aside>

<!-- Mobile Overlay Drawer -->
{#if mobileOpen}
  <div 
    class="mobile-backdrop" 
    onclick={closeFromBackdrop}
    onkeydown={(e) => e.key === 'Escape' && (mobileOpen = false)}
    role="button"
    tabindex="0"
    in:fade={{ duration: 150 }}
    out:fade={{ duration: 150 }}
  >
    <div 
      class="mobile-drawer"
      role="dialog"
      aria-modal="true"
      aria-label={tr('sidebar.navigation_menu')}
      tabindex="-1"
      in:fly={{ x: -280, duration: 250 }}
      out:fly={{ x: -280, duration: 200 }}
    >
      <div class="brand">
        <div class="logo-box">
          <span class="logo">⚡</span>
        </div>
        <div class="brand-text">
          <h2>ForgePanel</h2>
        </div>
        <button class="close-drawer" onclick={() => mobileOpen = false}>✕</button>
      </div>

      <nav>
        {#each tabs as tab}
          <button 
            class="nav-btn" 
            class:active={activeTab === tab.id}
            onclick={() => handleSelect(tab.id)}
          >
            <span class="icon">{tab.icon}</span>
            <span class="label">{tr(tab.labelKey)}</span>
          </button>
        {/each}
      </nav>
    </div>
  </div>
{/if}

<style>
  .lang-switch {
    display: flex;
    gap: 6px;
    margin-bottom: 12px;
  }
  .lang-btn {
    flex: 1;
    padding: 6px 8px;
    font-size: 12px;
    border-radius: 6px;
    cursor: pointer;
    color: rgba(255, 255, 255, 0.6);
    background: rgba(255, 255, 255, 0.04);
    border: 1px solid rgba(255, 255, 255, 0.08);
  }
  .lang-btn.active {
    color: #fff;
    background: rgba(255, 122, 26, 0.18);
    border-color: rgba(255, 122, 26, 0.45);
  }

  .sidebar {
    width: 260px;
    background: #0D121F;
    border-inline-end: 1px solid rgba(255, 255, 255, 0.07);
    padding: 24px 16px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    min-height: 100vh;
    box-sizing: border-box;
  }

  .brand {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 4px 8px 16px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.06);
    margin-bottom: 16px;
  }
  .logo-box {
    width: 36px;
    height: 36px;
    border-radius: 10px;
    background: linear-gradient(135deg, rgba(255,122,26,0.3) 0%, rgba(255,122,26,0.05) 100%);
    border: 1px solid rgba(255,122,26,0.4);
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: 0 4px 12px rgba(255,122,26,0.2);
  }
  .logo { font-size: 18px; }
  .brand-text h2 { margin: 0; font-size: 17px; font-weight: 700; color: #fff; letter-spacing: -0.02em; }
  .version-tag { font-size: 10px; color: #FF7A1A; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }

  nav { display: flex; flex-direction: column; gap: 6px; }
  .nav-btn {
    display: flex;
    align-items: center;
    gap: 12px;
    width: 100%;
    min-height: 44px;
    padding: 10px 14px;
    background: transparent;
    border: 1px solid transparent;
    border-radius: 10px;
    color: rgba(255, 255, 255, 0.65);
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1);
    position: relative;
    text-align: start;
  }
  .nav-btn:hover {
    background: rgba(255, 255, 255, 0.04);
    color: #fff;
    transform: translateX(3px);
  }
  .nav-btn.active {
    background: linear-gradient(90deg, rgba(255, 122, 26, 0.16) 0%, rgba(255, 122, 26, 0.04) 100%);
    border-color: rgba(255, 122, 26, 0.3);
    color: #FF7A1A;
    font-weight: 650;
  }
  .icon { font-size: 16px; }

  .sidebar-footer {
    padding-top: 16px;
    border-top: 1px solid rgba(255, 255, 255, 0.06);
  }
  .status-pulse {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 12px;
    color: rgba(255, 255, 255, 0.5);
  }
  .pulse-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #27D17C;
    box-shadow: 0 0 10px #27D17C;
    animation: pulse 2s infinite;
  }
  @keyframes pulse {
    0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(39, 209, 124, 0.7); }
    70% { transform: scale(1); box-shadow: 0 0 0 6px rgba(39, 209, 124, 0); }
    100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(39, 209, 124, 0); }
  }

  .mobile-backdrop {
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(0, 0, 0, 0.75);
    backdrop-filter: blur(8px);
    z-index: 1000;
  }
  .mobile-drawer {
    width: 280px;
    height: 100vh;
    background: #0D121F;
    border-inline-end: 1px solid rgba(255, 255, 255, 0.1);
    padding: 24px 16px;
    box-sizing: border-box;
    display: flex;
    flex-direction: column;
  }
  .close-drawer {
    margin-inline-start: auto;
    background: none;
    border: none;
    color: rgba(255,255,255,0.6);
    font-size: 18px;
    padding: 4px 8px;
    cursor: pointer;
  }

  @media (max-width: 768px) {
    .desktop-only { display: none; }
  }
</style>
