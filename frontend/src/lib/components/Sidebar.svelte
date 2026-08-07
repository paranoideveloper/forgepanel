<script lang="ts">
  import { fly, fade } from 'svelte/transition';

  let { activeTab, mobileOpen = $bindable(false), onTabChange } = $props<{
    activeTab: string;
    mobileOpen?: boolean;
    onTabChange: (tab: string) => void;
  }>();

  const tabs = [
    { id: 'overview', label: 'Overview', icon: '📊' },
    { id: 'inbounds', label: 'Inbounds', icon: '🔌' },
    { id: 'users', label: 'Users & Subscriptions', icon: '👥' },
    { id: 'nodes', label: 'Node Cluster', icon: '🌐' },
    { id: 'studio', label: 'Config Studio', icon: '⚙️' },
    { id: 'domains', label: 'Domains', icon: '🌍' },
    { id: 'forgedns', label: 'ForgeDNS', icon: '🛰️' },
    { id: 'certs', label: 'Certificates & TLS', icon: '🔒' },
    { id: 'system', label: 'System & Security', icon: '🛠️' }
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
      <span class="version-tag">v1.5.0</span>
    </div>
  </div>

  <nav>
    {#each tabs as t}
      <button 
        class="nav-btn" 
        class:active={activeTab === t.id}
        onclick={() => handleSelect(t.id)}
      >
        <span class="icon">{t.icon}</span>
        <span class="label">{t.label}</span>
      </button>
    {/each}
  </nav>

  <div class="sidebar-footer">
    <div class="status-pulse">
      <span class="pulse-dot"></span>
      <span>Control Plane Online</span>
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
      aria-label="Navigation menu"
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
        {#each tabs as t}
          <button 
            class="nav-btn" 
            class:active={activeTab === t.id}
            onclick={() => handleSelect(t.id)}
          >
            <span class="icon">{t.icon}</span>
            <span class="label">{t.label}</span>
          </button>
        {/each}
      </nav>
    </div>
  </div>
{/if}

<style>
  .sidebar {
    width: 260px;
    background: #0D121F;
    border-right: 1px solid rgba(255, 255, 255, 0.07);
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
    text-align: left;
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
    border-right: 1px solid rgba(255, 255, 255, 0.1);
    padding: 24px 16px;
    box-sizing: border-box;
    display: flex;
    flex-direction: column;
  }
  .close-drawer {
    margin-left: auto;
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
