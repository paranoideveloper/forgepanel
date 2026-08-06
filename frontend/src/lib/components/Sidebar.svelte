<script lang="ts">
  let { activeTab, onTabChange } = $props<{
    activeTab: string;
    onTabChange: (tab: string) => void;
  }>();

  const tabs = [
    { id: 'overview', label: 'Overview', icon: '📊' },
    { id: 'users', label: 'Users & Subscriptions', icon: '👥' },
    { id: 'nodes', label: 'Node Cluster', icon: '🌐' },
    { id: 'studio', label: 'Config Studio', icon: '⚙️' },
    { id: 'forgedns', label: 'ForgeDNS', icon: '🛰️' },
    { id: 'certs', label: 'Certificates & TLS', icon: '🔒' },
    { id: 'system', label: 'System & Security', icon: '🛠️' }
  ];
</script>

<aside class="sidebar">
  <div class="brand">
    <span class="logo">⚡</span>
    <h2>ForgePanel</h2>
  </div>

  <nav>
    {#each tabs as t}
      <button 
        class="nav-btn" 
        class:active={activeTab === t.id}
        onclick={() => onTabChange(t.id)}
      >
        <span class="icon">{t.icon}</span>
        <span class="label">{t.label}</span>
      </button>
    {/each}
  </nav>
</aside>

<style>
  .sidebar {
    width: 260px;
    background: #0F1420;
    border-right: 1px solid rgba(255, 255, 255, 0.08);
    padding: 24px 16px;
    display: flex;
    flex-direction: column;
    gap: 24px;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 12px;
    padding-left: 8px;
  }
  .logo {
    font-size: 22px;
  }
  .brand h2 {
    margin: 0;
    font-size: 18px;
    font-weight: 700;
    color: #FF7A1A;
  }
  nav {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .nav-btn {
    display: flex;
    align-items: center;
    gap: 12px;
    width: 100%;
    padding: 12px 14px;
    background: none;
    border: none;
    border-radius: 10px;
    color: rgba(255, 255, 255, 0.65);
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
    text-align: left;
  }
  .nav-btn:hover {
    background: rgba(255, 255, 255, 0.05);
    color: #fff;
    transform: translateX(2px);
  }
  .nav-btn.active {
    background: rgba(255, 122, 26, 0.15);
    color: #FF7A1A;
    font-weight: 650;
  }
  .icon {
    font-size: 16px;
  }
</style>
