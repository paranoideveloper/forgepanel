/**
 * The panel UI: one self-contained HTML document, no external assets.
 *
 * Everything is inline because a Worker has no static-asset origin to serve
 * from, and because a page that pulls a CDN script is a page whose behaviour a
 * third party controls. It also means the panel keeps working on a network that
 * blocks the CDN — which, for this product's users, is the normal case.
 */

export function panelHTML(securePath: string, needsSetup: boolean): string {
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ForgeEdge</title>
<style>
:root{--bg:#0b0f17;--panel:#111827;--line:#1f2937;--fg:#e5e7eb;--mut:#9ca3af;--acc:#38bdf8;--ok:#34d399;--bad:#f87171}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 ui-sans-serif,system-ui,-apple-system,sans-serif}
header{padding:1rem 1.25rem;border-bottom:1px solid var(--line);display:flex;gap:.75rem;align-items:baseline;flex-wrap:wrap}
h1{font-size:1.1rem;margin:0;letter-spacing:.02em}
.mut{color:var(--mut)}
main{max-width:960px;margin:0 auto;padding:1.25rem}
section{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:1rem;margin-bottom:1rem}
h2{font-size:.95rem;margin:0 0 .75rem;color:var(--acc)}
label{display:block;margin:.5rem 0 .2rem;font-size:.8rem;color:var(--mut)}
input,select,textarea{width:100%;background:#0b1220;color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:.45rem .6rem;font:inherit}
textarea{min-height:5rem;font-family:ui-monospace,monospace;font-size:.8rem}
button{background:var(--acc);color:#04202b;border:0;border-radius:6px;padding:.5rem .9rem;font-weight:600;cursor:pointer}
button.ghost{background:transparent;color:var(--fg);border:1px solid var(--line)}
button.danger{background:var(--bad);color:#2a0707}
.row{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:.75rem}
.actions{display:flex;gap:.5rem;flex-wrap:wrap;margin-top:.9rem}
pre{background:#0b1220;border:1px solid var(--line);border-radius:6px;padding:.7rem;overflow:auto;font-size:.78rem;max-height:22rem}
.chk{display:flex;align-items:center;gap:.45rem;margin:.3rem 0}
.chk input{width:auto}
#toast{position:fixed;right:1rem;bottom:1rem;background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--acc);border-radius:6px;padding:.6rem .9rem;display:none;max-width:24rem}
code{background:#0b1220;padding:.1em .35em;border-radius:4px}
</style></head><body>
<header><h1>ForgeEdge</h1><span class="mut">ForgePanel on Cloudflare Workers</span></header>
<main>

<section id="login" ${needsSetup ? '' : ''}>
  <h2>${needsSetup ? 'Set an admin password' : 'Sign in'}</h2>
  <p class="mut">${needsSetup
      ? 'No password is set yet. Choose one now — until you do, anyone who learns the secure path can administer this Worker.'
      : 'The secure path alone does not grant administration.'}</p>
  <label for="pw">Password</label>
  <input id="pw" type="password" autocomplete="current-password">
  <div class="actions">
    <button id="doLogin">${needsSetup ? 'Set password' : 'Sign in'}</button>
  </div>
</section>

<div id="app" hidden>
<section>
  <h2>Endpoints</h2>
  <pre id="endpoints">loading…</pre>
  <div class="actions">
    <button class="ghost" id="refreshStatus">Refresh</button>
    <button class="danger" id="rotate">Regenerate secure path</button>
  </div>
</section>

<section>
  <h2>Configuration</h2>
  <p class="mut">The full config as JSON. Everything lives in KV — there are no environment variables to edit in the dashboard.</p>
  <textarea id="cfg" spellcheck="false" style="min-height:22rem"></textarea>
  <div class="actions">
    <button id="saveCfg">Save</button>
    <button class="ghost" id="reloadCfg">Reload</button>
  </div>
</section>

<section>
  <h2>Clean IPs</h2>
  <label for="probe">Probe a candidate (host or host:port)</label>
  <input id="probe" placeholder="cf.090227.xyz">
  <div class="actions">
    <button id="doProbe">Probe</button>
    <button class="ghost" id="doRefreshClean">Refresh from sources</button>
  </div>
  <pre id="cleanOut" hidden></pre>
</section>

<section>
  <h2>WARP + Amnezia</h2>
  <p class="mut">Free Cloudflare WARP becomes a WireGuard node and an AmneziaWG (DPI-obfuscated) node in every subscription. A Worker <b>cannot register WARP itself</b> — the edge refuses its request to Cloudflare's own WARP API — so registration runs off the edge. <b>ForgePanel does this for you</b> (Deploy → ⚡ WARP + Amnezia). For a standalone Worker, register elsewhere (e.g. <code>wgcf</code>) and paste the accounts below.</p>
  <label for="warpAccts">WARP accounts JSON <span class="mut">— an array of {privateKey, publicKey, warpIPv6, reserved}</span></label>
  <textarea id="warpAccts" spellcheck="false" placeholder='[{"privateKey":"…","publicKey":"…","warpIPv6":"2606:4700:…/128","reserved":"…"}]' style="min-height:7rem"></textarea>
  <div class="actions"><button id="storeWarp">Store accounts</button></div>
  <h2 style="margin-top:1.4rem">WARP endpoints</h2>
  <p class="mut">A Worker has no UDP socket, so latency can only be measured by your ForgePanel VPS in Backend Mode. Without one you get ranked candidates and no invented numbers.</p>
  <div class="actions"><button id="doScan">Scan</button></div>
  <pre id="warpOut" hidden></pre>
</section>

<section>
  <h2>Deployment</h2>
  <pre id="deployOut">loading…</pre>
  <div class="actions">
    <button class="ghost" id="checkUpdate">Check for updates</button>
  </div>
</section>
</div>
</main>
<div id="toast"></div>
<script>
const BASE = '/${securePath}';
const $ = (id) => document.getElementById(id);
let toastTimer;
function toast(msg, bad) {
  const t = $('toast');
  t.textContent = msg;
  t.style.borderLeftColor = bad ? 'var(--bad)' : 'var(--acc)';
  t.style.display = 'block';
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.style.display = 'none'; }, 4000);
}
async function api(path, opts) {
  const res = await fetch(BASE + '/api' + path, { credentials: 'same-origin', ...opts });
  const data = await res.json().catch(() => ({ success: false, message: 'bad response' }));
  if (!data.success) throw new Error(data.message || ('HTTP ' + res.status));
  return data.body;
}
async function loadAll() {
  const st = await api('/status');
  $('endpoints').textContent = JSON.stringify(st, null, 2);
  const cfg = await api('/config');
  $('cfg').value = JSON.stringify(cfg, null, 2);
  $('deployOut').textContent = JSON.stringify(st.deployment || { note: 'no Cloudflare credential bound; self-management disabled' }, null, 2);
}
$('doLogin').onclick = async () => {
  try {
    await api('/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: $('pw').value }),
    });
    $('login').hidden = true;
    $('app').hidden = false;
    await loadAll();
    toast('Signed in');
  } catch (e) { toast(e.message, true); }
};
$('refreshStatus').onclick = () => loadAll().then(() => toast('Refreshed')).catch(e => toast(e.message, true));
$('reloadCfg').onclick = () => loadAll().then(() => toast('Reloaded')).catch(e => toast(e.message, true));
$('saveCfg').onclick = async () => {
  try {
    const parsed = JSON.parse($('cfg').value);
    await api('/config', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(parsed) });
    toast('Saved');
  } catch (e) { toast(e.message, true); }
};
$('rotate').onclick = async () => {
  if (!confirm('Every existing panel and subscription URL stops working. Continue?')) return;
  try {
    const body = await api('/rotate-path', { method: 'POST' });
    alert('New panel URL:\\n' + location.origin + '/' + body.securePath + '/panel');
    location.href = '/' + body.securePath + '/panel';
  } catch (e) { toast(e.message, true); }
};
$('doProbe').onclick = async () => {
  try {
    const body = await api('/clean-ip/probe?target=' + encodeURIComponent($('probe').value));
    $('cleanOut').hidden = false;
    $('cleanOut').textContent = JSON.stringify(body, null, 2);
  } catch (e) { toast(e.message, true); }
};
$('doRefreshClean').onclick = async () => {
  try {
    const body = await api('/clean-ip/refresh', { method: 'POST' });
    $('cleanOut').hidden = false;
    $('cleanOut').textContent = JSON.stringify(body, null, 2);
  } catch (e) { toast(e.message, true); }
};
$('doScan').onclick = async () => {
  try {
    const body = await api('/warp/scan', { method: 'POST' });
    $('warpOut').hidden = false;
    $('warpOut').textContent = JSON.stringify(body, null, 2);
  } catch (e) { toast(e.message, true); }
};
$('storeWarp').onclick = async () => {
  let parsed;
  try {
    parsed = JSON.parse($('warpAccts').value);
  } catch (e) { toast('That is not valid JSON', true); return; }
  // Accept either a bare array or a { accounts: [...] } envelope.
  const accounts = Array.isArray(parsed) ? parsed : parsed.accounts;
  try {
    const body = await api('/warp/accounts', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ accounts }),
    });
    toast('Stored ' + (Array.isArray(body) ? body.length : 0) + ' WARP account(s)');
  } catch (e) { toast(e.message, true); }
};
$('checkUpdate').onclick = async () => {
  try {
    const body = await api('/update-check');
    $('deployOut').textContent = JSON.stringify(body, null, 2);
  } catch (e) { toast(e.message, true); }
};
// A live session means the login card is unnecessary.
api('/status').then(async (st) => {
  $('login').hidden = true;
  $('app').hidden = false;
  $('endpoints').textContent = JSON.stringify(st, null, 2);
  const cfg = await api('/config');
  $('cfg').value = JSON.stringify(cfg, null, 2);
  $('deployOut').textContent = JSON.stringify(st.deployment || { note: 'no Cloudflare credential bound; self-management disabled' }, null, 2);
}).catch(() => { /* not signed in yet */ });
</script>
</body></html>`;
}
