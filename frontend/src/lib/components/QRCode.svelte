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
    background: #0F1420;
    border-radius: 12px;
    border: 1px solid rgba(255, 255, 255, 0.1);
  }
</style>
