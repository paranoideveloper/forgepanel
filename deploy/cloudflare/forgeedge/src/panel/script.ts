/**
 * The panel's client script, returned as a string and inlined by `ui.ts`.
 *
 * It is a string rather than a bundled module because a Worker serves no static
 * assets: the whole panel is one document. Keeping it in its own file keeps the
 * shell readable and keeps this under the size where nobody reads it either.
 *
 * The form is GENERATED from the `GROUPS` table serialised into the page, so
 * there is one renderer per control kind instead of sixty hand-written blocks
 * and sixty matching bind/read calls — which is where a form this size normally
 * rots, one silently unsaved field at a time.
 */
export function panelScript(): string {
  return String.raw`
const BASE = '/' + SECURE_PATH;
const $ = (id) => document.getElementById(id);
let CFG = {};        // last loaded config
let DRAFT = {};      // edits not yet saved
let STATUS = {};

/* ---------- helpers ---------- */
let toastTimer;
function toast(msg, bad) {
  const t = $('toast');
  t.textContent = msg;
  t.style.borderLeftColor = bad ? 'var(--bad)' : 'var(--acc)';
  t.style.display = 'block';
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.style.display = 'none'; }, 4500);
}
async function api(path, opts) {
  const res = await fetch(BASE + '/api' + path, { credentials: 'same-origin', ...opts });
  const data = await res.json().catch(() => ({ success: false, message: 'bad response' }));
  if (!data.success) throw new Error(data.message || ('HTTP ' + res.status));
  return data.body;
}
function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
}
// Dotted get/set, so a field's path is the only thing that binds it.
function dget(obj, path) {
  return path.split('.').reduce((o, k) => (o == null ? undefined : o[k]), obj);
}
function dset(obj, path, val) {
  const parts = path.split('.');
  const last = parts.pop();
  let cur = obj;
  for (const p of parts) { if (cur[p] == null || typeof cur[p] !== 'object') cur[p] = {}; cur = cur[p]; }
  cur[last] = val;
}

/* ---------- rendering ---------- */
function controlHTML(f) {
  const id = 'f_' + f.path.replace(/\./g, '_');
  const help = f.help ? '<div class="help">' + esc(f.help) + '</div>' : '';
  const wide = (f.kind === 'lines' || f.kind === 'csv') ? ' wide' : '';
  const caution = f.caution ? ' caution' : '';

  if (f.kind === 'bool') {
    return '<div class="f' + caution + '" data-path="' + f.path + '" data-label="' + esc(f.label) + '">' +
      '<label class="sw"><input type="checkbox" id="' + id + '"><span class="track"></span>' +
      '<span class="txt">' + esc(f.label) + '</span></label>' + help + '</div>';
  }
  let ctl;
  if (f.kind === 'select') {
    ctl = '<select id="' + id + '">' +
      (f.options || []).map((o) => '<option value="' + esc(o) + '">' + esc(o) + '</option>').join('') +
      '</select>';
  } else if (f.kind === 'lines') {
    ctl = '<textarea id="' + id + '" spellcheck="false" placeholder="' + esc(f.placeholder || '') + '"></textarea>';
  } else if (f.kind === 'number') {
    ctl = '<input type="number" id="' + id + '"' +
      (f.min != null ? ' min="' + f.min + '"' : '') + (f.max != null ? ' max="' + f.max + '"' : '') + '>';
  } else {
    const t = f.kind === 'password' ? 'password' : 'text';
    ctl = '<input type="' + t + '" id="' + id + '" placeholder="' + esc(f.placeholder || '') + '"' +
      (f.kind === 'password' ? ' autocomplete="off"' : '') + '>';
  }
  return '<div class="f' + wide + caution + '" data-path="' + f.path + '" data-label="' + esc(f.label) + '">' +
    '<label for="' + id + '">' + esc(f.label) + '</label>' + ctl + help + '</div>';
}

function renderPanes() {
  const parts = [];

  parts.push('<section data-pane="overview"><h2>Overview</h2>' +
    '<p class="blurb">What this Worker is serving right now.</p>' +
    '<div class="grid">' +
      '<div class="f"><label>Import page — send this to family</label>' +
        '<input type="text" id="shareLanding" readonly onclick="this.select()"></div>' +
      '<div class="f"><label>Subscription URL</label>' +
        '<input type="text" id="shareSub" readonly onclick="this.select()"></div>' +
    '</div>' +
    '<p class="blurb" style="margin-top:.7rem">DPI fallbacks, for when every proxy IP is blocked: ' +
      '<a id="shareServerless" target="_blank">serverless</a> · ' +
      '<a id="shareSmart" target="_blank">smart-fragment</a></p>' +
    '<div class="stats" id="stats"></div>' +
    '<details style="margin-top:.9rem"><summary class="blurb" style="cursor:pointer">Raw status</summary>' +
      '<pre id="endpoints" style="margin-top:.5rem">loading…</pre></details>' +
    '<div class="actions"><button class="btn ghost" id="refreshStatus">Refresh</button>' +
      '<button class="btn danger" id="rotate">Regenerate secure path</button></div></section>');

  for (const g of GROUPS) {
    parts.push('<section data-pane="' + g.id + '"><h2>' + esc(g.title) + '</h2>' +
      (g.blurb ? '<p class="blurb">' + esc(g.blurb) + '</p>' : '') +
      '<div class="grid">' + g.fields.map(controlHTML).join('') + '</div></section>');
  }

  parts.push('<section data-pane="tools"><h2>Tools</h2>' +
    '<p class="blurb">Actions that run on the edge rather than changing configuration.</p>' +
    '<div class="f"><label for="probe">Probe a clean-IP candidate (host or host:port)</label>' +
      '<input type="text" id="probe" placeholder="cf.090227.xyz"></div>' +
    '<div class="actions"><button class="btn" id="doProbe">Probe</button>' +
      '<button class="btn ghost" id="doRefreshClean">Refresh clean IPs</button>' +
      '<button class="btn ghost" id="doRefreshExt">Refresh external subs</button>' +
      '<button class="btn ghost" id="doScan">Scan WARP endpoints</button>' +
      '<button class="btn ghost" id="checkUpdate">Check for updates</button></div>' +
    '<pre id="toolOut" hidden></pre>' +
    '<h2 style="margin-top:1.4rem">WARP accounts</h2>' +
    '<p class="blurb">A Worker <b>cannot register WARP itself</b> — the edge refuses its own request to ' +
      "Cloudflare's WARP API — so registration happens off the edge. ForgePanel does this for you " +
      '(Deploy → WARP + Amnezia); standalone, register with <code>wgcf</code> and paste the accounts here.</p>' +
    '<div class="f wide"><label for="warpAccts">Accounts JSON — [{privateKey, publicKey, warpIPv6, reserved}]</label>' +
      '<textarea id="warpAccts" spellcheck="false"></textarea></div>' +
    '<div class="actions"><button class="btn" id="storeWarp">Store accounts</button></div>' +
    '<pre id="deployOut" style="margin-top:1rem">loading…</pre></section>');

  parts.push('<section data-pane="expert"><h2>Expert</h2>' +
    '<p class="blurb">The raw configuration. Everything above edits this same object; anything without a ' +
      'control yet (UDP noise packets) is edited here. Saving from this tab replaces the whole config.</p>' +
    '<div class="f wide"><textarea id="cfg" spellcheck="false" style="min-height:24rem"></textarea></div>' +
    '<div class="actions"><button class="btn" id="saveRaw">Save raw JSON</button>' +
      '<button class="btn ghost" id="reloadCfg">Reload</button></div></section>');

  $('panes').innerHTML = parts.join('');
}

/* ---------- binding ---------- */
function fieldsFlat() { return GROUPS.flatMap((g) => g.fields); }

function fillForm() {
  for (const f of fieldsFlat()) {
    const el = $('f_' + f.path.replace(/\./g, '_'));
    if (!el) continue;
    const v = dget(DRAFT, f.path);
    if (f.kind === 'bool') el.checked = !!v;
    else if (f.kind === 'lines') el.value = Array.isArray(v) ? v.join('\n') : (v == null ? '' : String(v));
    else if (f.kind === 'csv') el.value = Array.isArray(v) ? v.join(',') : (v == null ? '' : String(v));
    else el.value = v == null ? '' : String(v);
  }
  $('cfg').value = JSON.stringify(DRAFT, null, 2);
}

function readControl(f, el) {
  if (f.kind === 'bool') return el.checked;
  if (f.kind === 'number') { const n = Number(el.value); return Number.isFinite(n) ? n : 0; }
  if (f.kind === 'lines' || f.kind === 'csv') {
    const sep = f.kind === 'csv' ? ',' : '\n';
    const parts = el.value.split(sep).map((s) => s.trim()).filter(Boolean);
    // A list that held numbers must go back as numbers: ports are compared
    // numerically downstream, and ["443"] silently matches nothing.
    const orig = dget(CFG, f.path);
    if (Array.isArray(orig) && orig.length && typeof orig[0] === 'number') {
      return parts.map(Number).filter((n) => Number.isFinite(n));
    }
    return parts;
  }
  return el.value;
}

function bindInputs() {
  for (const f of fieldsFlat()) {
    const el = $('f_' + f.path.replace(/\./g, '_'));
    if (!el) continue;
    const ev = (f.kind === 'bool' || f.kind === 'select') ? 'change' : 'input';
    el.addEventListener(ev, () => {
      dset(DRAFT, f.path, readControl(f, el));
      refreshSaveBar();
      renderStats();
    });
  }
}

// Compared by value, not by a dirty flag: typing a change and typing it back is
// not an edit, and a counter that says "1 unsaved" for an unchanged form is a
// counter nobody trusts twice.
function changedPaths() {
  return fieldsFlat()
    .map((f) => f.path)
    .filter((p) => JSON.stringify(dget(DRAFT, p)) !== JSON.stringify(dget(CFG, p)));
}
function refreshSaveBar() {
  const n = changedPaths().length;
  $('savecount').textContent = n === 1 ? '1 unsaved change' : n + ' unsaved changes';
  $('savebar').classList.toggle('show', n > 0);
}

/* ---------- navigation, search, theme ---------- */
function showPane(id) {
  document.querySelectorAll('[data-pane]').forEach((s) => { s.hidden = s.dataset.pane !== id; });
  document.querySelectorAll('.navitem').forEach((b) => b.classList.toggle('on', b.dataset.go === id));
  window.scrollTo({ top: 0 });
}
function wireNav() {
  document.querySelectorAll('.navitem').forEach((b) => {
    b.onclick = () => showPane(b.dataset.go);
  });
  showPane('overview');
}

// Search exists because sixty settings across twelve groups is more than anyone
// remembers the location of. It jumps to the field and marks it.
function wireSearch() {
  const box = $('search');
  box.hidden = false;
  box.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter') return;
    const q = box.value.trim().toLowerCase();
    if (!q) return;
    for (const g of GROUPS) {
      for (const f of g.fields) {
        if (f.label.toLowerCase().includes(q) || f.path.toLowerCase().includes(q)) {
          showPane(g.id);
          const el = document.querySelector('[data-path="' + f.path + '"]');
          if (el) {
            el.scrollIntoView({ block: 'center' });
            el.classList.add('hit');
            setTimeout(() => el.classList.remove('hit'), 2000);
          }
          return;
        }
      }
    }
    toast('No setting matches ' + q, true);
  });
}
function wireTheme() {
  const KEY = 'forgeedge.theme';
  // Wrapped: a private window or a browser blocking site data throws on access,
  // and a theme toggle must never be the reason the panel fails to load.
  let saved = null;
  try { saved = localStorage.getItem(KEY); } catch (_) {}
  if (saved) document.documentElement.dataset.theme = saved;
  $('theme').onclick = () => {
    const dark = matchMedia('(prefers-color-scheme: dark)').matches;
    const cur = document.documentElement.dataset.theme || (dark ? 'dark' : 'light');
    const next = cur === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem(KEY, next); } catch (_) {}
  };
}

/* ---------- load and save ---------- */
function tile(label, value, tone) {
  return '<div class="stat' + (tone ? ' ' + tone : '') + '">' +
    '<div class="k">' + esc(label) + '</div><div class="v">' + esc(value) + '</div></div>';
}

// The overview used to be a JSON dump. A dump is not a status: it makes the
// reader do the work of finding the three facts that matter, every time.
function renderStats() {
  const on = (b) => (b ? 'on' : 'off');
  const protos = Array.isArray(DRAFT.protocols) ? DRAFT.protocols.join(' + ') : '—';
  const ports = Array.isArray(DRAFT.ports) ? DRAFT.ports.length : 0;
  const clean = Array.isArray(DRAFT.cleanIPs) ? DRAFT.cleanIPs.length : 0;
  const ext = STATUS.externalSubs || {};
  $('stats').innerHTML = [
    tile('Protocols', protos || 'none', protos ? 'ok' : 'bad'),
    tile('Ports advertised', String(ports), ports ? 'ok' : 'bad'),
    tile('Clean IPs', String(clean), clean ? 'ok' : ''),
    tile('Outbound', DRAFT.proxyIPMode === 'off' ? 'direct' : String(DRAFT.proxyIPMode || '—'),
      DRAFT.proxyIPMode === 'off' ? 'warn' : 'ok'),
    tile('Backend mode', on(DRAFT.backend && DRAFT.backend.enabled)),
    tile('Fragmentation', on(DRAFT.fragment && DRAFT.fragment.enabled)),
    tile('External configs', ext.count == null ? '—' : ext.count + ' from ' + ext.sources),
    tile('Limits', on(DRAFT.limits && DRAFT.limits.enabled)),
  ].join('');
}

async function loadAll() {
  STATUS = await api('/status');
  $('endpoints').textContent = JSON.stringify(STATUS, null, 2);
  if (STATUS.landingShared) $('shareLanding').value = STATUS.landingShared;
  if (STATUS.subShared) $('shareSub').value = STATUS.subShared;
  if (STATUS.serverless) $('shareServerless').href = STATUS.serverless;
  if (STATUS.smartFragment) $('shareSmart').href = STATUS.smartFragment;
  $('deployOut').textContent = JSON.stringify(
    STATUS.deployment || { note: 'no Cloudflare credential bound; self-management disabled' }, null, 2);
  if (STATUS.version) $('verPill').textContent = 'v' + STATUS.version;

  CFG = await api('/config');
  DRAFT = JSON.parse(JSON.stringify(CFG));
  fillForm();
  renderStats();
  refreshSaveBar();
}

async function saveConfig(obj) {
  await api('/config', {
    method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(obj),
  });
  CFG = JSON.parse(JSON.stringify(obj));
  DRAFT = JSON.parse(JSON.stringify(obj));
  fillForm();
  refreshSaveBar();
}

function wireActions() {
  $('save').onclick = async () => {
    try { await saveConfig(DRAFT); toast('Saved'); } catch (e) { toast(e.message, true); }
  };
  $('discard').onclick = () => {
    DRAFT = JSON.parse(JSON.stringify(CFG));
    fillForm(); refreshSaveBar(); toast('Changes discarded');
  };
  $('saveRaw').onclick = async () => {
    try { await saveConfig(JSON.parse($('cfg').value)); toast('Saved'); }
    catch (e) { toast(e.message, true); }
  };
  $('reloadCfg').onclick = () => loadAll().then(() => toast('Reloaded')).catch((e) => toast(e.message, true));
  $('refreshStatus').onclick = () => loadAll().then(() => toast('Refreshed')).catch((e) => toast(e.message, true));

  $('rotate').onclick = async () => {
    if (!confirm('Every existing panel and subscription URL stops working. Continue?')) return;
    try {
      const body = await api('/rotate-path', { method: 'POST' });
      alert('New panel URL:\n' + location.origin + '/' + body.securePath + '/panel');
      location.href = '/' + body.securePath + '/panel';
    } catch (e) { toast(e.message, true); }
  };

  const out = (v) => { const p = $('toolOut'); p.hidden = false; p.textContent = JSON.stringify(v, null, 2); };
  const tool = (id, fn, msg) => {
    $(id).onclick = async () => {
      try { out(await fn()); toast(msg); } catch (e) { toast(e.message, true); }
    };
  };
  tool('doProbe', () => api('/clean-ip/probe?target=' + encodeURIComponent($('probe').value)), 'Probed');
  tool('doRefreshClean', () => api('/clean-ip/refresh', { method: 'POST' }), 'Clean IPs refreshed');
  tool('doRefreshExt', () => api('/external/refresh', { method: 'POST' }), 'External subs refreshed');
  tool('doScan', () => api('/warp/scan'), 'Scanned');
  tool('checkUpdate', () => api('/update-check'), 'Checked');
  $('storeWarp').onclick = async () => {
    try {
      await api('/warp/accounts', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: $('warpAccts').value,
      });
      toast('WARP accounts stored');
    } catch (e) { toast(e.message, true); }
  };
}

$('doLogin').onclick = async () => {
  try {
    await api('/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: $('pw').value }),
    });
    $('login').hidden = true;
    $('app').hidden = false;
    renderPanes(); bindInputs(); wireNav(); wireSearch(); wireActions();
    await loadAll();
    toast('Signed in');
  } catch (e) { toast(e.message, true); }
};
$('pw').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('doLogin').click(); });
wireTheme();

// Leaving with unsaved edits loses them silently otherwise; this form is large
// enough that a mis-click costs real work.
addEventListener('beforeunload', (e) => {
  if (changedPaths().length) { e.preventDefault(); e.returnValue = ''; }
});
`;
}
