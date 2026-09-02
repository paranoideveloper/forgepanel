<script lang="ts">
	import { tr } from '$lib/i18n';
  // A usage chart drawn as plain SVG.
  //
  // No charting library: one would be the largest dependency in the panel, for
  // a bar chart and an axis. The whole component is under 150 lines and has no
  // supply chain.
  //
  // It is a BAR chart, not a line. Each point is bytes transferred within a
  // bucket — a quantity per interval, not a level sampled at an instant — and a
  // line drawn between them implies values that were never measured.

  export interface Point {
    bucket: string;
    bytes: number;
  }

  let {
    points = [],
    period = 'hour',
    height = 160,
    label = 'Traffic'
  } = $props<{
    points?: Point[];
    period?: string;
    height?: number;
    label?: string;
  }>();

  const W = 720;
  const PAD_L = 56;
  const PAD_B = 22;
  const PAD_T = 8;

  const max = $derived(points.reduce((m: number, p: Point) => Math.max(m, p.bytes), 0));
  const plotH = $derived(height - PAD_B - PAD_T);
  const plotW = $derived(W - PAD_L - 8);
  // A minimum bar width keeps a two-point series from rendering as two slabs
  // across the whole width.
  const barW = $derived(points.length ? Math.max(1, Math.min(28, plotW / points.length - 2)) : 0);

  function x(i: number): number {
    if (points.length <= 1) return PAD_L;
    return PAD_L + (i * plotW) / points.length;
  }

  function barHeight(bytes: number): number {
    // A zero max would divide by zero; an all-zero series is a flat baseline,
    // which is the honest rendering of "no traffic".
    if (max <= 0) return 0;
    return Math.max(bytes > 0 ? 1 : 0, (bytes / max) * plotH);
  }

  export function formatBytes(n: number): string {
    if (!n) return '0';
    const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    let v = n;
    let i = 0;
    while (v >= 1024 && i < units.length - 1) {
      v /= 1024;
      i++;
    }
    return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
  }

  function labelFor(iso: string): string {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return '';
    return period === 'day'
      ? d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
      : d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
  }

  // Three gridlines is enough to read a magnitude without turning the plot into
  // graph paper.
  const ticks = $derived(max > 0 ? [max, max / 2, 0] : [0]);

  // Label every nth bucket, so a 700-point series does not render an unreadable
  // smear of overlapping text.
  const labelEvery = $derived(Math.max(1, Math.ceil(points.length / 8)));

  const total = $derived(points.reduce((sum: number, p: Point) => sum + p.bytes, 0));
</script>

<figure class="chart">
  <figcaption>
    <span>{label}</span>
    <!-- The total is the number people actually want; the bars give it shape. -->
    <strong data-testid="chart-total">{formatBytes(total)}</strong>
  </figcaption>

  {#if points.length === 0}
    <p class="muted" data-testid="chart-empty">{tr('trafficchart.no_usage_recorded_in_this_period')}</p>
  {:else}
    <svg viewBox="0 0 {W} {height}" width="100%" height={height} role="img"
         aria-label="{label}: {formatBytes(total)} across {points.length} buckets">
      {#each ticks as t}
        {@const ty = PAD_T + plotH - barHeight(t)}
        <line x1={PAD_L} y1={ty} x2={W - 8} y2={ty} class="grid" />
        <text x={PAD_L - 8} y={ty + 4} class="tick" text-anchor="end">{formatBytes(t)}</text>
      {/each}

      {#each points as p, i}
        {@const h = barHeight(p.bytes)}
        <rect
          x={x(i)}
          y={PAD_T + plotH - h}
          width={barW}
          height={h}
          class="bar"
          data-testid="bar"
        ><title>{labelFor(p.bucket)} — {formatBytes(p.bytes)}</title></rect>
        {#if i % labelEvery === 0}
          <text x={x(i) + barW / 2} y={height - 6} class="tick" text-anchor="middle">
            {labelFor(p.bucket)}
          </text>
        {/if}
      {/each}
    </svg>
  {/if}
</figure>

<style>
  .chart { margin: 0; }
  figcaption {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    font-size: 12px;
    text-transform: uppercase;
    color: var(--t-5);
    margin-bottom: 8px;
  }
  figcaption strong { font-size: 15px; color: var(--fg); text-transform: none; }
  .grid { stroke: var(--ln-3); stroke-width: 1; }
  .tick { fill: var(--t-8); font-size: 10px; }
  .bar { fill: var(--acc); }
  .bar:hover { fill: var(--acc-2); }
  .muted { color: var(--t-6); font-size: 13px; }
</style>
