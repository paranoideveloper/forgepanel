<script lang="ts">
  import { generateQRCodeSVG } from '$lib/qrcode';

  let { value, size = 200 } = $props<{ value: string; size?: number }>();
  let svg = $derived(generateQRCodeSVG(value, size));
</script>

<div class="qr-wrapper">
  {@html svg}
</div>

<style>
  .qr-wrapper {
    display: inline-flex;
    padding: 12px;
    background: var(--bg);
    border-radius: 12px;
    border: 1px solid var(--ln-4);
  }
</style>
