<script lang="ts">
  import { fade, scale } from 'svelte/transition';

  let { title = '', isOpen = false, onClose, children } = $props<{
    title?: string;
    isOpen: boolean;
    onClose: () => void;
    children?: any;
  }>();

  function closeFromBackdrop(event: MouseEvent) {
    if (event.target === event.currentTarget) {
      onClose();
    }
  }
</script>

{#if isOpen}
  <div 
    class="modal-backdrop" 
    onclick={closeFromBackdrop}
    onkeydown={(e) => e.key === 'Escape' && onClose()}
    role="button"
    tabindex="0"
    data-testid="backdrop"
    in:fade={{ duration: 150 }}
    out:fade={{ duration: 150 }}
  >
    <div 
      class="modal-dialog" 
      role="dialog"
      aria-modal="true"
      aria-label={title}
      tabindex="-1"
      in:scale={{ start: 0.95, duration: 200 }}
      out:scale={{ start: 0.95, duration: 150 }}
    >
      <div class="modal-header">
        <h3>{title}</h3>
        <button class="close-btn" onclick={onClose}>✕</button>
      </div>
      <div class="modal-body">
        {@render children?.()}
      </div>
    </div>
  </div>
{/if}

<style>
  .modal-backdrop {
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: var(--scrim);
    backdrop-filter: blur(6px);
    z-index: 1000;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 20px;
  }
  .modal-dialog {
    background: var(--card);
    border: 1px solid var(--ln-4);
    border-radius: 16px;
    width: 100%;
    max-width: 560px;
    box-shadow: 0 20px 50px var(--shadow);
    overflow: hidden;
  }
  .modal-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 18px 24px;
    border-bottom: 1px solid var(--ln-3);
  }
  .modal-header h3 {
    margin: 0;
    font-size: 16px;
    font-weight: 650;
    color: var(--fg);
  }
  .close-btn {
    background: none;
    border: none;
    color: var(--t-7);
    font-size: 16px;
    cursor: pointer;
    padding: 4px 8px;
    border-radius: 6px;
  }
  .close-btn:hover {
    color: var(--fg);
    background: var(--ln-4);
  }
  .modal-body {
    padding: 24px;
    max-height: 80vh;
    overflow-y: auto;
  }
</style>
