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
  <h2>Dashboard Overview</h2>
  <button class="btn-primary" onclick={loadOverview}>Refresh</button>
</div>

{#if loading}
  <p class="muted">Loading dashboard status...</p>
{:else if health}
  <div class="metrics-grid">
    <div class="metric-card">
      <span class="label">System Status</span>
      <span class="value ok">{health.status}</span>
    </div>
    <div class="metric-card">
      <span class="label">Core Version</span>
      <span class="value">{health.version}</span>
    </div>
    <div class="metric-card">
      <span class="label">Node Cluster</span>
      <span class="value">{health.nodes_online} / {health.nodes_total} Online</span>
    </div>
    <div class="metric-card">
      <span class="label">Uptime</span>
      <span class="value">{formatUptime(health.uptime_seconds)}</span>
    </div>
  </div>

  <div class="card" style="margin-top:24px">
    <h3>Quick System Navigation</h3>
    <p class="muted">Manage your users, nodes, protocols, and DNS tunnels directly from the left sidebar without page reloads.</p>
  </div>
{/if}

<style>
  .view-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
  .view-header h2 { margin: 0; font-size: 20px; font-weight: 650; }
  .metrics-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; }
  .metric-card { background: #141A24; border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; padding: 20px; }
  .metric-card .label { display: block; font-size: 12px; color: rgba(255,255,255,0.6); margin-bottom: 8px; }
  .metric-card .value { font-size: 22px; font-weight: 700; color: #fff; }
  .value.ok { color: #27D17C; }
  .card { background: #141A24; border: 1px solid rgba(255,255,255,0.08); border-radius: 14px; padding: 20px; }
  .card h3 { margin: 0 0 8px; font-size: 14px; text-transform: uppercase; color: rgba(255,255,255,0.7); }
  .btn-primary { background: #FF7A1A; color: #1a1204; border: none; font-weight: 700; padding: 10px 16px; border-radius: 8px; cursor: pointer; }
  .muted { color: rgba(255,255,255,0.6); font-size: 14px; }
</style>
