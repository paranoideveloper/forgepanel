/**
 * The panel shell: one self-contained HTML document, no external assets.
 *
 * Everything is inline because a Worker has no static-asset origin to serve
 * from, and because a page that pulls a CDN script is a page whose behaviour a
 * third party controls. It also means the panel keeps working on a network that
 * blocks the CDN — which, for this product's users, is the normal case.
 *
 * The controls are not written out here. They are generated at load time from
 * the table in `fields.ts`, which is serialised into the page below, so adding a
 * setting is one row rather than a block of markup plus a block of binding code.
 */

import { GROUPS } from './fields';
import { panelScript } from './script';

export function panelHTML(securePath: string, needsSetup: boolean): string {
  const nav = GROUPS.map(
    (g, i) =>
      `<button class="navitem${i === 0 ? ' on' : ''}" data-go="${g.id}">${esc(g.title)}</button>`,
  ).join('');

  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ForgeEdge</title>
<style>
/* Light is the base and dark is the override, so a token defined once is never
   missing in one of the two themes — the usual way a theme-aware page ends up
   with black text on a black card. */
:root{
  --bg:#f6f7f9; --card:#ffffff; --line:#e3e6ea; --raised:#f0f2f5;
  --fg:#111827; --mut:#5b6472; --dim:#8b95a3;
  --acc:#1d68d8; --acc-fg:#ffffff; --acc-soft:#e8f0fd;
  --ok:#0a7f4f; --warn:#a35b00; --bad:#c0271e; --bad-fg:#ffffff;
  --r-card:14px; --r-ui:9px; --shadow:0 1px 2px rgba(16,24,40,.06),0 1px 3px rgba(16,24,40,.1);
  /* Native widgets — the select's arrow, scrollbars, focus rings — follow this
     rather than staying light on a dark page. */
  color-scheme:light;
}
:root:not([data-theme="light"]){ @media (prefers-color-scheme: dark){
  --bg:#0b0f17; --card:#111827; --line:#1f2937; --raised:#0b1220;
  --fg:#e5e7eb; --mut:#9ca3af; --dim:#6b7280;
  --acc:#38bdf8; --acc-fg:#04202b; --acc-soft:#0e2b3b;
  --ok:#34d399; --warn:#fbbf24; --bad:#f87171; --bad-fg:#2a0707;
  --shadow:0 1px 2px rgba(0,0,0,.4);
  color-scheme:dark;
}}
:root[data-theme="dark"]{
  --bg:#0b0f17; --card:#111827; --line:#1f2937; --raised:#0b1220;
  --fg:#e5e7eb; --mut:#9ca3af; --dim:#6b7280;
  --acc:#38bdf8; --acc-fg:#04202b; --acc-soft:#0e2b3b;
  --ok:#34d399; --warn:#fbbf24; --bad:#f87171; --bad-fg:#2a0707;
  --shadow:0 1px 2px rgba(0,0,0,.4);
  color-scheme:dark;
}
*{box-sizing:border-box}
html,body{background:var(--bg)}
body{margin:0;color:var(--fg);font:14px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;-webkit-font-smoothing:antialiased}
a{color:var(--acc)}

header{position:sticky;top:0;z-index:20;background:var(--card);border-bottom:1px solid var(--line);
  padding:.7rem 1rem;display:flex;gap:.75rem;align-items:center;flex-wrap:wrap}
.brand{font-weight:650;letter-spacing:.01em}
.brand .dot{color:var(--acc)}
.grow{flex:1}
.pill{font-size:.72rem;padding:.15rem .5rem;border-radius:999px;background:var(--raised);
  border:1px solid var(--line);color:var(--mut)}
.pill.ok{color:var(--ok)} .pill.bad{color:var(--bad)}

.wrap{max-width:1180px;margin:0 auto;padding:1rem;display:grid;grid-template-columns:210px 1fr;gap:1rem;align-items:start}
@media (max-width:860px){ .wrap{grid-template-columns:1fr} nav.side{position:static;flex-direction:row;overflow-x:auto} }

nav.side{position:sticky;top:4rem;display:flex;flex-direction:column;gap:2px;
  background:var(--card);border:1px solid var(--line);border-radius:var(--r-card);padding:.4rem}
.navitem{all:unset;cursor:pointer;padding:.5rem .65rem;border-radius:var(--r-ui);color:var(--mut);
  font-size:.85rem;white-space:nowrap}
.navitem:hover{background:var(--raised);color:var(--fg)}
.navitem.on{background:var(--acc-soft);color:var(--acc);font-weight:600}

section{background:var(--card);border:1px solid var(--line);border-radius:var(--r-card);
  padding:1rem 1.1rem;margin-bottom:1rem;box-shadow:var(--shadow)}
section h2{font-size:.98rem;margin:0 0 .15rem}
section .blurb{color:var(--mut);font-size:.83rem;margin:0 0 .9rem}

.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:.85rem}
.f{min-width:0}
.f label{display:block;font-size:.79rem;color:var(--mut);margin-bottom:.25rem}
.f .help{font-size:.74rem;color:var(--dim);margin-top:.25rem}
.f.caution .help{color:var(--warn)}
input[type=text],input[type=password],input[type=number],select,textarea{
  width:100%;background:var(--raised);color:var(--fg);border:1px solid var(--line);
  border-radius:var(--r-ui);padding:.45rem .6rem;font:inherit}
input:focus,select:focus,textarea:focus{outline:2px solid var(--acc);outline-offset:-1px}
textarea{min-height:5.5rem;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.8rem;resize:vertical}
.f.wide{grid-column:1/-1}

/* A switch rather than a bare checkbox: with 22 booleans on one page, state has
   to be readable at a glance and not just on inspection.
   Selected as .f label.sw rather than a lone .sw: the switch IS the field's
   label, and .f label{display:block} above outranks a lone class, which silently
   left every toggle as a block — the track then computed display:inline, and an
   inline box ignores width and height, so all 22 collapsed to a bare knob drawn
   on top of their own text. It looked like a missing stylesheet and was a
   specificity tie. */
.f label.sw{display:flex;align-items:center;gap:.6rem;padding:.4rem 0;margin:0}
.sw input{position:absolute;opacity:0;width:0;height:0}
.sw .track{width:34px;height:20px;border-radius:999px;background:var(--line);position:relative;
  transition:background .15s;flex:none}
.sw .track::after{content:"";position:absolute;top:2px;left:2px;width:16px;height:16px;border-radius:50%;
  background:var(--card);transition:transform .15s;box-shadow:0 1px 2px rgba(0,0,0,.3)}
.sw input:checked + .track{background:var(--acc)}
.sw input:checked + .track::after{transform:translateX(14px)}
.sw input:focus-visible + .track{outline:2px solid var(--acc);outline-offset:2px}
.sw .txt{font-size:.85rem}

button.btn{background:var(--acc);color:var(--acc-fg);border:0;border-radius:var(--r-ui);
  padding:.5rem .9rem;font:inherit;font-weight:600;cursor:pointer}
button.btn:disabled{opacity:.5;cursor:default}
button.ghost{background:transparent;color:var(--fg);border:1px solid var(--line)}
button.danger{background:var(--bad);color:var(--bad-fg)}
.actions{display:flex;gap:.5rem;flex-wrap:wrap;margin-top:.9rem}

pre{background:var(--raised);border:1px solid var(--line);border-radius:var(--r-ui);
  padding:.7rem;overflow:auto;font-size:.78rem;max-height:22rem;margin:0}
code{background:var(--raised);padding:.1em .35em;border-radius:4px;font-size:.85em}

/* The save bar. Per-section saves make it impossible to tell what is pending
   across a form this size, so there is one bar and it counts. */
#savebar{position:fixed;left:50%;transform:translateX(-50%) translateY(150%);bottom:1rem;z-index:30;
  background:var(--card);border:1px solid var(--line);border-radius:999px;box-shadow:var(--shadow);
  padding:.5rem .6rem .5rem 1rem;display:flex;gap:.6rem;align-items:center;transition:transform .18s}
#savebar.show{transform:translateX(-50%) translateY(0)}
#savecount{font-size:.83rem;color:var(--mut)}

#toast{position:fixed;right:1rem;bottom:1rem;z-index:40;background:var(--card);border:1px solid var(--line);
  border-left:3px solid var(--acc);border-radius:var(--r-ui);padding:.6rem .9rem;display:none;max-width:24rem;
  box-shadow:var(--shadow)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:.6rem;margin-top:.4rem}
.stat{background:var(--raised);border:1px solid var(--line);border-radius:var(--r-ui);padding:.55rem .7rem}
.stat .k{font-size:.72rem;color:var(--mut);text-transform:uppercase;letter-spacing:.04em}
.stat .v{font-size:1.02rem;font-weight:600;margin-top:.15rem}
.stat.ok .v{color:var(--ok)} .stat.warn .v{color:var(--warn)} .stat.bad .v{color:var(--bad)}
details summary::marker{color:var(--mut)}
.hit{outline:2px solid var(--acc);outline-offset:3px;border-radius:var(--r-ui)}
#search{max-width:15rem}
.login{max-width:26rem;margin:3rem auto}
</style></head><body>

<header>
  <span class="brand">Forge<span class="dot">Edge</span></span>
  <span class="pill" id="verPill">—</span>
  <span class="grow"></span>
  <input id="search" type="text" placeholder="Search settings…" hidden>
  <button class="btn ghost" id="theme" title="Theme">◐</button>
</header>

<section class="login" id="login">
  <h2>${needsSetup ? 'Set an admin password' : 'Sign in'}</h2>
  <p class="blurb">${
    needsSetup
      ? 'No password is set yet. Choose one now — until you do, anyone who learns the secure path can administer this Worker.'
      : 'The secure path alone does not grant administration.'
  }</p>
  <div class="f"><label for="pw">Password</label><input id="pw" type="password" autocomplete="current-password"></div>
  <div class="actions"><button class="btn" id="doLogin">${needsSetup ? 'Set password' : 'Sign in'}</button></div>
</section>

<div class="wrap" id="app" hidden>
  <nav class="side">
    <button class="navitem on" data-go="overview">Overview</button>
    ${nav}
    <button class="navitem" data-go="tools">Tools</button>
    <button class="navitem" data-go="expert">Expert</button>
  </nav>
  <main id="panes"></main>
</div>

<div id="savebar"><span id="savecount"></span>
  <button class="btn ghost" id="discard">Discard</button>
  <button class="btn" id="save">Save</button></div>
<div id="toast"></div>

<script>
const SECURE_PATH = ${jsonForScript(securePath)};
const GROUPS = ${jsonForScript(GROUPS)};
${panelScript()}
</script>
</body></html>`;
}

/**
 * JSON for embedding inside a <script> element.
 *
 * JSON.stringify does not escape `<`, so a value containing `</script>` closes
 * the block and everything after it is parsed as markup. Today nothing reaches
 * here that could: securePath is either randomly generated or read from
 * env.SECURE_PATH behind a /^[a-z0-9-]{8,64}$/ test, and GROUPS is a literal in
 * this repository. That is a property of two callers rather than of this
 * function, and it is the kind of guarantee that quietly stops holding — a
 * field label with an angle bracket, a future setting echoed into the page — so
 * the escaping lives here where the embedding happens.
 */
function jsonForScript(value: unknown): string {
  return JSON.stringify(value).replace(/</g, '\\u003c');
}

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string,
  );
}
