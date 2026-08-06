<script lang="ts">
  import { onMount } from 'svelte';
  import { apiFetch } from '$lib/api';
  import type { SystemHealth } from '$lib/types';
  import { showToast } from '$lib/components/Toast.svelte';

  let health = $state<SystemHealth | null>(null);
  let loading = $state(true);

  async function loadOverview() {
    loading = true;
    try {
      health = await apiFetch<SystemHealth>('/health');
    } catch (err: any) {
      showToast(err.message || 'Failed to load system status', 'error');
    } finally {
      loading = false;
    }
  }

  function formatUptime(seconds?: number): string {
    if (!seconds) return '0s';
    const hrs = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    return `${hrs}h ${mins}m`;
  }

  onMount(() => {
    loadOverview();
  });
</script>

<div class="view-header">
  <div>
    <h2>Dashboard Overview</h2>
    <p class="header-desc">Real-time control-plane health & node cluster metrics</p>
  </div>
  <button class="btn-primary" onclick={loadOverview}>Refresh</button>
</div>

{#if loading}
  <div class="skeleton-grid">
    <div class="skeleton-card"></div>
    <div class="skeleton-card"></div>
    <div class="skeleton-card"></div>
    <div class="skeleton-card"></div>
  </div>
{:else if health}
  <div class="metrics-grid">
    <div class="metric-card">
      <div class="card-icon status-icon">🟢</div>
      <div class="card-info">
        <span class="label">System Status</span>
        <span class="value ok">{health.status}</span>
      </div>
    </div>

    <div class="metric-card">
      <div class="card-icon">⚡</div>
      <div class="card-info">
        <span class="label">Core Version</span>
        <span class="value">{health.version}</span>
      </div>
    </div>

    <div class="metric-card">
      <div class="card-icon">🌐</div>
      <div class="card-info">
        <span class="label">Node Cluster</span>
        <span class="value">{health.nodes_online} / {health.nodes_total} <span class="unit">Online</span></span>
      </div>
    </div>

    <div class="metric-card">
      <div class="card-icon">⏱️</div>
      <div class="card-info">
        <span class="label">Uptime</span>
        <span class="value">{formatUptime(health.uptime_seconds)}</span>
      </div>
    </div>
  </div>

  <div class="card nav-hint-card">
    <h3>Quick Navigation</h3>
    <p class="muted">
      Access user management, remote node cluster enrollment, protocol engine configuration, and DNS tunnel features using the left navigation sidebar.
    </p>
  </div>
{/if}

<style>
  .view-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 24px;
    gap: 16px;
  }
  .view-header h2 { margin: 0; font-size: 22px; font-weight: 700; letter-spacing: -0.02em; }
  .header-desc { margin: 4px 0 0; font-size: 13px; color: rgba(255, 255, 255, 0.55); }

  .metrics-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
  }
  .metric-card {
    background: rgba(20, 26, 36, 0.7);
    backdrop-filter: blur(12px);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 14px;
    padding: 20px;
    display: flex;
    align-items: center;
    gap: 16px;
    transition: transform 0.2s cubic-bezier(0.16, 1, 0.3, 1), border-color 0.2s ease;
  }
  .metric-card:hover {
    transform: translateY(-2px);
    border-color: rgba(255, 122, 26, 0.3);
  }
  .card-icon {
    width: 44px; height: 44px;
    border-radius: 12px;
    background: rgba(255, 255, 255, 0.04);
    border: 1px solid rgba(255, 255, 255, 0.08);
    display: flex; align-items: center; justify-content: center;
    font-size: 20px;
  }
  .card-info { display: flex; flex-direction: column; }
  .metric-card .label { font-size: 12px; color: rgba(255, 255, 255, 0.55); font-weight: 500; }
  .metric-card .value { font-size: 20px; font-weight: 700; color: #fff; margin-top: 2px; }
  .value.ok { color: #27D17C; }
  .unit { font-size: 13px; color: rgba(255, 255, 255, 0.6); font-weight: 500; }

  .card {
    background: rgba(20, 26, 36, 0.7);
    backdrop-filter: blur(12px);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 16px;
    padding: 24px;
  }
  .nav-hint-card h3 { margin: 0 0 8px; font-size: 14px; text-transform: uppercase; color: #FF7A1A; letter-spacing: 0.05em; }
  .muted { color: rgba(255, 255, 255, 0.65); font-size: 14px; line-height: 1.6; margin: 0; }

  .btn-primary {
    background: #FF7A1A;
    color: #1a1204;
    border: none;
    font-weight: 700;
    padding: 10px 18px;
    border-radius: 10px;
    cursor: pointer;
    min-height: 40px;
    transition: transform 0.15s ease;
  }
  .btn-primary:active { transform: scale(0.97); }

  .skeleton-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; }
  .skeleton-card { height: 84px; background: rgba(255, 255, 255, 0.04); border-radius: 14px; }
</style>
