<script lang="ts">
	import { tr } from '$lib/i18n';
  import { onMount } from 'svelte';
  import { apiFetch } from '$lib/api';
  import type { SystemHealth } from '$lib/types';
  import { showToast } from '$lib/components/Toast.svelte';

  let health = $state<SystemHealth | null>(null);
  let loading = $state(true);

  async function loadOverview() {
    loading = true;
    try {
      health = await apiFetch<SystemHealth>('/admin/overview');
    } catch (err: any) {
      showToast(err.message || tr('overview.failed_to_load_system_status'), 'error');
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
    <h2>{tr('overview.dashboard_overview')}</h2>
    <p class="header-desc">{tr('overview.real_time_control_plane_health_node')}</p>
  </div>
  <button class="btn-primary" onclick={loadOverview}>{tr('overview.refresh')}</button>
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
        <span class="label">{tr('overview.system_status')}</span>
        <span class="value ok">{health.status}</span>
      </div>
    </div>

    <div class="metric-card">
      <div class="card-icon">⚡</div>
      <div class="card-info">
        <span class="label">{tr('overview.core_version')}</span>
        <span class="value">{health.version}</span>
      </div>
    </div>

    <div class="metric-card">
      <div class="card-icon">🌐</div>
      <div class="card-info">
        <span class="label">{tr('overview.node_cluster')}</span>
        <span class="value">{health.nodes_online} / {health.nodes_total} <span class="unit">{tr('overview.online')}</span></span>
      </div>
    </div>

    <div class="metric-card">
      <div class="card-icon">⏱️</div>
      <div class="card-info">
        <span class="label">{tr('overview.uptime')}</span>
        <span class="value">{formatUptime(health.uptime_seconds)}</span>
      </div>
    </div>
  </div>

  <div class="card nav-hint-card">
    <h3>{tr('overview.quick_navigation')}</h3>
    <p class="muted">
      {tr('overview.access_user_management_remote_node_cluster')}
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
  .header-desc { margin: 4px 0 0; font-size: 13px; color: var(--t-6); }

  .metrics-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
  }
  .metric-card {
    background: var(--card-glass-2);
    backdrop-filter: blur(12px);
    border: 1px solid var(--ln-3);
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
    background: var(--ln-1);
    border: 1px solid var(--ln-3);
    display: flex; align-items: center; justify-content: center;
    font-size: 20px;
  }
  .card-info { display: flex; flex-direction: column; }
  .metric-card .label { font-size: 12px; color: var(--t-6); font-weight: 500; }
  .metric-card .value { font-size: 20px; font-weight: 700; color: var(--fg); margin-top: 2px; }
  .value.ok { color: var(--ok); }
  .unit { font-size: 13px; color: var(--t-5); font-weight: 500; }

  .card {
    background: var(--card-glass-2);
    backdrop-filter: blur(12px);
    border: 1px solid var(--ln-3);
    border-radius: 16px;
    padding: 24px;
  }
  .nav-hint-card h3 { margin: 0 0 8px; font-size: 14px; text-transform: uppercase; color: var(--acc); letter-spacing: 0.05em; }
  .muted { color: var(--t-4); font-size: 14px; line-height: 1.6; margin: 0; }

  .btn-primary {
    background: var(--acc);
    color: var(--acc-soft);
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
  .skeleton-card { height: 84px; background: var(--ln-1); border-radius: 14px; }
</style>
