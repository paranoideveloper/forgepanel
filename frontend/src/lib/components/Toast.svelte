<script lang="ts" module>
  import { writable } from 'svelte/store';

  export interface ToastMessage {
    id: number;
    type: 'success' | 'error' | 'info';
    text: string;
  }

  export const toasts = writable<ToastMessage[]>([]);

  let nextId = 1;
  export function showToast(text: string, type: 'success' | 'error' | 'info' = 'info') {
    const id = nextId++;
    toasts.update(all => [...all, { id, type, text }]);
    setTimeout(() => {
      toasts.update(all => all.filter(t => t.id !== id));
    }, 4000);
  }
</script>

<script lang="ts">
  import { fly, fade } from 'svelte/transition';
</script>

<div class="toast-container">
  {#each $toasts as t (t.id)}
    <div 
      class="toast toast-{t.type}" 
      in:fly={{ y: 20, duration: 250 }} 
      out:fade={{ duration: 150 }}
    >
      <span class="icon">
        {#if t.type === 'success'}✓{:else if t.type === 'error'}✕{:else}ℹ{/if}
      </span>
      <span class="text">{t.text}</span>
    </div>
  {/each}
</div>

<style>
  .toast-container {
    position: fixed;
    bottom: 24px;
    inset-inline-end: 24px;
    z-index: 9999;
    display: flex;
    flex-direction: column;
    gap: 10px;
    pointer-events: none;
  }
  .toast {
    pointer-events: auto;
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 12px 18px;
    border-radius: 10px;
    font-size: 14px;
    font-weight: 500;
    color: var(--fg);
    box-shadow: 0 8px 24px var(--shadow);
    backdrop-filter: blur(8px);
  }
  .toast-success { background: rgba(39, 209, 124, 0.9); color: var(--bg-deep); }
  .toast-error { background: rgba(255, 77, 77, 0.9); color: var(--fg); }
  .toast-info { background: rgba(255, 122, 26, 0.9); color: var(--acc-soft); }
  .icon { font-weight: 700; }
</style>
