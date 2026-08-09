/**
 * The end-user landing page: `/<securePath>/import/<sub_token>`.
 *
 * Unlike the admin panel, this holds no secret an ordinary subscriber shouldn't
 * see — it is built FROM their own subscription token, which already lives in
 * their config. It gives them one-tap import into the common clients plus a QR
 * to scan from a phone, so onboarding a family member is "open link, tap your
 * app" instead of "copy this URL into the right box".
 */

import { qrSvg } from './qr';

interface ImportTarget {
  label: string;
  /** Builds the client's deep-link from the subscription URL. */
  link: (subUrl: string) => string;
}

// The deep-link schemes the mainstream clients register. Where a client wants
// the raw URL after a prefix (Streisand/Hiddify) we pass it verbatim; the rest
// take it url-encoded as a query param.
const TARGETS: ImportTarget[] = [
  { label: 'v2rayNG', link: (u) => `v2rayng://install-sub?url=${encodeURIComponent(u)}` },
  { label: 'Streisand', link: (u) => `streisand://import/${u}` },
  { label: 'Hiddify', link: (u) => `hiddify://import/${u}` },
  { label: 'sing-box', link: (u) => `sing-box://import-remote-profile?url=${encodeURIComponent(u)}` },
  { label: 'Clash Meta', link: (u) => `clash://install-config?url=${encodeURIComponent(u)}` },
  { label: 'Mihomo Party', link: (u) => `clashmeta://install-config?url=${encodeURIComponent(u)}` },
  { label: 'Shadowrocket', link: (u) => `shadowrocket://add/sub://${btoa(u)}` },
];

// Direct per-format links, for pasting into anything the buttons miss.
const FORMATS = ['v2ray', 'clash', 'sing-box', 'xray'];

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] as string
  ));
}

export function landingHTML(host: string, securePath: string, subToken: string, title: string): string {
  const subUrl = `https://${host}/${securePath}/sub/${subToken}`;
  const buttons = TARGETS.map((t) =>
    `<a class="app" href="${esc(t.link(subUrl))}">${esc(t.label)}</a>`).join('');
  const formats = FORMATS.map((f) =>
    `<a class="fmt" href="${esc(`${subUrl}/${f}`)}">${esc(f)}</a>`).join('');

  return `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>${esc(title)}</title>
<style>
  :root { color-scheme: light dark; --bg:#0F1420; --card:#141A24; --line:rgba(255,255,255,.10); --fg:#E7ECF3; --mut:rgba(231,236,243,.6); --acc:#27D17C; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--fg); font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif; padding:24px 16px; }
  .wrap { max-width:520px; margin:0 auto; }
  h1 { font-size:20px; margin:0 0 4px; }
  .sub { color:var(--mut); margin:0 0 20px; font-size:13px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:16px; padding:20px; margin-bottom:16px; }
  .qr { display:flex; justify-content:center; margin-bottom:8px; }
  .qr svg { border-radius:10px; }
  .urlrow { display:flex; gap:8px; margin-top:8px; }
  .urlrow input { flex:1; background:var(--bg); border:1px solid var(--line); color:var(--fg); border-radius:10px; padding:10px; font-size:12px; }
  button, .app, .fmt { font:inherit; cursor:pointer; }
  #copy { background:var(--acc); border:none; color:#04110A; font-weight:600; border-radius:10px; padding:0 16px; }
  h2 { font-size:13px; text-transform:uppercase; letter-spacing:.05em; color:var(--mut); margin:0 0 10px; }
  .apps { display:grid; grid-template-columns:1fr 1fr; gap:10px; }
  .app { display:block; text-align:center; text-decoration:none; background:var(--bg); border:1px solid var(--line); color:var(--fg); border-radius:12px; padding:14px; font-weight:600; }
  .app:hover { border-color:var(--acc); }
  .fmts { display:flex; flex-wrap:wrap; gap:8px; margin-top:12px; }
  .fmt { text-decoration:none; color:var(--mut); border:1px solid var(--line); border-radius:20px; padding:6px 12px; font-size:12px; }
  .hint { color:var(--mut); font-size:12px; margin:12px 0 0; }
</style></head><body><div class="wrap">
  <h1>${esc(title)}</h1>
  <p class="sub">Add this subscription to your app — tap a button, or scan the code.</p>
  <div class="card">
    <div class="qr">${qrSvg(subUrl)}</div>
    <div class="urlrow">
      <input id="url" value="${esc(subUrl)}" readonly onclick="this.select()">
      <button id="copy">Copy</button>
    </div>
  </div>
  <div class="card">
    <h2>One-tap import</h2>
    <div class="apps">${buttons}</div>
    <div class="fmts"><span class="hint" style="margin:0">Direct:</span>${formats}</div>
    <p class="hint">If a button does nothing, your app isn't installed — copy the URL above and paste it into the app's "Add subscription".</p>
  </div>
</div><script>
  document.getElementById('copy').addEventListener('click', async () => {
    const el = document.getElementById('url'); el.select();
    try { await navigator.clipboard.writeText(el.value); } catch (e) { document.execCommand('copy'); }
    const b = document.getElementById('copy'); b.textContent = 'Copied'; setTimeout(() => b.textContent = 'Copy', 1500);
  });
</script></body></html>`;
}
