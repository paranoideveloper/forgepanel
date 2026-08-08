// ForgeEdge — a Cloudflare Worker that is BOTH a VLESS-over-WebSocket proxy on
// the Cloudflare edge AND a free-config generator + subscription panel.
//
// Same idea as BPB-Worker-Panel / Nova-Proxy: a client's traffic rides
// client → (clean CF edge IP) → this Worker → destination, so it works from
// networks that throttle the default Cloudflare anycast IPs (e.g. Iran). The
// Worker also serves a password-protected panel and subscription links that
// point at a rotation of proven-clean edge IPs on Cloudflare's TLS ports.
//
// Deploy: `wrangler deploy`, or paste this into a Worker in the CF dashboard.
// Configure with these variables (Worker → Settings → Variables), all optional:
//   UUID       the VLESS id clients authenticate with (auto-derived if unset)
//   PROXYIP    a fallback proxy host[:port] for destinations the edge can't
//              reach directly (Cloudflare→Cloudflare is blocked); e.g. a relay
//   SUBPATH    the secret path prefix for the panel/subscription (default = UUID)
//   DNS_RESOLVER  DoH resolver for UDP/DNS (default 1.1.1.1)
//
// Single file on purpose — no build step, no dependencies.

import { connect } from 'cloudflare:sockets';

// ---------------------------------------------------------------------------
// Static config. Clean edge IPs are Cloudflare ranges that tend to stay
// reachable where the anycast default is throttled. Ports are Cloudflare's
// TLS-enabled proxy ports (only these terminate TLS for a Worker hostname).
// ---------------------------------------------------------------------------
const CF_TLS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
const CLEAN_IPS = [
  '162.159.36.1', '162.159.46.1', '162.159.192.1', '162.159.193.1',
  '104.16.132.229', '104.17.148.22', '104.18.5.39', '104.19.42.34',
  '188.114.96.3', '188.114.97.3', '188.114.98.224', '188.114.99.224',
  '141.101.113.5', '190.93.245.5', '198.41.192.167', '172.67.71.55',
];
// Hostnames some networks resolve to clean edges — handy as SNI-agnostic entries.
const CLEAN_DOMAINS = ['creativecommons.org', 'www.speedtest.net', 'cf.090227.xyz'];

export default {
  async fetch(request, env) {
    try {
      const uuid = normalizeUUID(env.UUID) || (await deriveUUID(request));
      const upgrade = request.headers.get('Upgrade');
      if (upgrade && upgrade.toLowerCase() === 'websocket') {
        return await vlessOverWS(request, uuid, env);
      }
      return handleHTTP(request, uuid, env);
    } catch (err) {
      return new Response('err: ' + (err && err.stack ? err.stack : err), { status: 500 });
    }
  },
};

// ---------------------------------------------------------------------------
// HTTP surface: panel + subscription, hidden behind a secret path so the root
// looks like nothing (a plain 404-ish page), the way BPB/Nova hide theirs.
// ---------------------------------------------------------------------------
function handleHTTP(request, uuid, env) {
  const url = new URL(request.url);
  const host = request.headers.get('Host') || url.hostname;
  const base = (env.SUBPATH && env.SUBPATH.trim()) || uuid;
  const p = url.pathname;

  if (p === `/${base}` || p === `/${base}/` || p === `/${base}/panel`) {
    return html(panelHTML(uuid, host, base), 200);
  }
  if (p === `/${base}/sub` || p === `/sub/${base}`) {
    return text(subscription(uuid, host), 200);
  }
  if (p === `/${base}/sub/singbox` || p === `/${base}/singbox`) {
    return json(singboxSub(uuid, host), 200);
  }
  if (p === `/${base}/sub/clash` || p === `/${base}/clash`) {
    return text(clashSub(uuid, host), 200);
  }
  // Everything else: a benign page (masquerade). Never reveal the panel path.
  return html(`<!doctype html><meta charset=utf-8><title>OK</title><body style="font-family:system-ui;background:#0b0f1a;color:#8aa">
<div style="max-width:640px;margin:12vh auto;padding:24px">It works.</div></body>`, 200);
}

// ---------------------------------------------------------------------------
// VLESS over WebSocket. The client speaks VLESS; the first WS frame carries the
// VLESS header (uuid + target addr/port). We validate the uuid, dial the target
// with Cloudflare's socket API, and pipe bytes both ways.
// ---------------------------------------------------------------------------
async function vlessOverWS(request, uuid, env) {
  const pair = new WebSocketPair();
  const [client, ws] = [pair[0], pair[1]];
  ws.accept();

  let remote = { socket: null };
  let udpWrite = null;

  const early = request.headers.get('sec-websocket-protocol') || '';
  const readable = wsReadable(ws, early);

  readable.pipeTo(new WritableStream({
    async write(chunk) {
      if (udpWrite) return udpWrite(chunk);
      if (remote.socket) {
        const w = remote.socket.writable.getWriter();
        await w.write(chunk); w.releaseLock();
        return;
      }
      const h = parseVlessHeader(chunk, uuid);
      if (h.error) throw new Error(h.error);
      const resp = new Uint8Array([h.version, 0]); // VLESS response header
      if (h.isUDP) {
        if (h.port !== 53) throw new Error('UDP only supported for DNS (:53)');
        udpWrite = await makeUDP(ws, resp, env);
        udpWrite(h.payload);
        return;
      }
      await openAndRelay(remote, h.address, h.port, h.payload, ws, resp, env);
    },
    close() { safeClose(remote.socket); },
    abort() { safeClose(remote.socket); },
  })).catch(() => safeClose(remote.socket));

  return new Response(null, { status: 101, webSocket: client });
}

// openAndRelay dials the target, writes the first payload, and starts the
// remote→ws relay IN THE BACKGROUND (no await on the pipe). This is essential:
// the WS write handler must return promptly so later client frames can still be
// written to remote.socket — a TLS handshake to the destination needs several
// client→server frames, so awaiting the whole relay here would deadlock it.
async function openAndRelay(remote, address, port, payload, ws, respHeader, env) {
  async function dial(host, p) {
    const socket = connect({ hostname: host, port: p });
    remote.socket = socket;
    const w = socket.writable.getWriter();
    await w.write(payload);
    w.releaseLock();
    return socket;
  }
  let socket;
  try {
    socket = await dial(address, port);
  } catch (e) {
    // Cloudflare→Cloudflare is refused and some dests are unreachable from the
    // edge; fall back to a relay if one is configured.
    if (!env.PROXYIP) throw e;
    const [ph, pp] = splitHostPort(env.PROXYIP, port);
    socket = await dial(ph, pp);
  }
  let sentHeader = false;
  socket.readable.pipeTo(new WritableStream({
    write(chunk) {
      if (ws.readyState !== 1) throw new Error('ws closed');
      if (!sentHeader) {
        const merged = new Uint8Array(respHeader.byteLength + chunk.byteLength);
        merged.set(respHeader, 0);
        merged.set(new Uint8Array(chunk), respHeader.byteLength);
        ws.send(merged);
        sentHeader = true;
      } else {
        ws.send(chunk);
      }
    },
    close() { safeClose(remote.socket); },
    abort() { safeClose(remote.socket); },
  })).catch(() => safeClose(remote.socket));
}

// Minimal UDP/DNS: forward the query to a DoH resolver and stream the answer
// back framed the way VLESS-UDP expects (2-byte length prefix per datagram).
async function makeUDP(ws, respHeader, env) {
  const doh = env.DNS_RESOLVER ? `https://${env.DNS_RESOLVER}/dns-query` : 'https://1.1.1.1/dns-query';
  let sentHeader = false;
  return async (chunk) => {
    // chunk may contain multiple length-prefixed datagrams.
    let i = 0;
    while (i < chunk.byteLength) {
      const len = (chunk[i] << 8) | chunk[i + 1];
      const q = chunk.slice(i + 2, i + 2 + len);
      i += 2 + len;
      const r = await fetch(doh, { method: 'POST', headers: { 'content-type': 'application/dns-message' }, body: q });
      const ab = new Uint8Array(await r.arrayBuffer());
      const size = new Uint8Array([(ab.byteLength >> 8) & 0xff, ab.byteLength & 0xff]);
      if (ws.readyState !== 1) return;
      if (!sentHeader) {
        const m = new Uint8Array(respHeader.byteLength + size.byteLength + ab.byteLength);
        m.set(respHeader, 0); m.set(size, respHeader.byteLength); m.set(ab, respHeader.byteLength + size.byteLength);
        ws.send(m); sentHeader = true;
      } else {
        const m = new Uint8Array(size.byteLength + ab.byteLength);
        m.set(size, 0); m.set(ab, size.byteLength);
        ws.send(m);
      }
    }
  };
}

// Parse the VLESS request header. Layout:
//   [0]      version
//   [1..16]  uuid (16 bytes)
//   [17]     addon length M
//   [18..]   M addon bytes (ignored)
//   [+0]     command (1 tcp, 2 udp, 3 mux)
//   [+1..2]  port (big-endian)
//   [+3]     address type (1 ipv4, 2 domain, 3 ipv6)
//   [+4..]   address
//   [rest]   payload
function parseVlessHeader(buf, uuid) {
  const b = new Uint8Array(buf);
  if (b.byteLength < 24) return { error: 'header too short' };
  const version = b[0];
  const id = b.slice(1, 17);
  if (bytesToUUID(id) !== uuid) return { error: 'uuid mismatch' };
  const m = b[17];
  let i = 18 + m;
  const cmd = b[i++];
  let isUDP = false;
  if (cmd === 2) isUDP = true;
  else if (cmd !== 1) return { error: 'unsupported command ' + cmd };
  const port = (b[i] << 8) | b[i + 1]; i += 2;
  const atype = b[i++];
  let address = '';
  if (atype === 1) { address = `${b[i]}.${b[i + 1]}.${b[i + 2]}.${b[i + 3]}`; i += 4; }
  else if (atype === 2) { const l = b[i++]; address = new TextDecoder().decode(b.slice(i, i + l)); i += l; }
  else if (atype === 3) {
    const parts = []; for (let k = 0; k < 8; k++) { parts.push(((b[i] << 8) | b[i + 1]).toString(16)); i += 2; }
    address = parts.join(':');
  } else return { error: 'bad atype ' + atype };
  return { version, isUDP, port, address, payload: b.slice(i) };
}

// ---------------------------------------------------------------------------
// Config generation. Build a rotation of VLESS-WS-TLS entries pointing at the
// Worker host through clean edge IPs on Cloudflare's TLS ports.
// ---------------------------------------------------------------------------
// buildConfigs returns structured entries so every output format uses the same
// source of truth — no re-parsing a URI (which silently dropped :443 as the
// https default port and produced server_port: 0 in the sing-box output).
function buildConfigs(uuid, host) {
  const path = '/?ed=2560';
  const cfgs = [];
  const add = (addr, port, tag) => cfgs.push({ addr, port, host, sni: host, path, tag, uuid });
  add(host, 443, 'ForgeEdge · direct'); // the Worker's own anycast hostname
  let n = 0;
  for (const ip of CLEAN_IPS) { add(ip, CF_TLS_PORTS[n % CF_TLS_PORTS.length], `ForgeEdge · ${ip}`); n++; }
  for (const d of CLEAN_DOMAINS) add(d, 443, `ForgeEdge · ${d}`);
  return cfgs;
}
function toURI(c) {
  return `vless://${c.uuid}@${c.addr}:${c.port}?encryption=none&security=tls&sni=${c.sni}&fp=chrome&type=ws&host=${c.host}&path=${encodeURIComponent(c.path)}#${encodeURIComponent(c.tag)}`;
}
function subscription(uuid, host) { return btoa(buildConfigs(uuid, host).map(toURI).join('\n')); }
function singboxSub(uuid, host) {
  return {
    outbounds: buildConfigs(uuid, host).map((c) => ({
      type: 'vless', tag: c.tag, server: c.addr, server_port: c.port, uuid: c.uuid,
      tls: { enabled: true, server_name: c.sni, utls: { enabled: true, fingerprint: 'chrome' } },
      transport: { type: 'ws', path: c.path, headers: { Host: c.host } },
    })),
  };
}
function clashSub(uuid, host) {
  const cs = buildConfigs(uuid, host);
  const proxies = cs.map((c) => `  - {name: "${c.tag}", type: vless, server: ${c.addr}, port: ${c.port}, uuid: ${c.uuid}, tls: true, servername: ${c.sni}, network: ws, udp: true, ws-opts: {path: "${c.path}", headers: {Host: ${c.host}}}}`);
  const names = cs.map((c) => `      - "${c.tag}"`);
  return `proxies:\n${proxies.join('\n')}\nproxy-groups:\n  - name: ForgeEdge\n    type: select\n    proxies:\n${names.join('\n')}\nrules:\n  - MATCH,ForgeEdge\n`;
}

// ---------------------------------------------------------------------------
// Panel UI
// ---------------------------------------------------------------------------
function panelHTML(uuid, host, base) {
  const list = buildConfigs(uuid, host);
  const subURL = `https://${host}/${base}/sub`;
  const rows = list.map((c) => {
    const u = toURI(c);
    return `<div class="cfg"><div class="nm">${esc(c.tag)}</div><code>${esc(u)}</code>
      <button onclick='cp(${JSON.stringify(u)})'>copy</button></div>`;
  }).join('');
  return `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>ForgeEdge</title>
<style>
:root{--bg:#0b0f1a;--card:#131a2b;--fg:#e6ecff;--mut:#8a97b8;--acc:#ff7a1a}
*{box-sizing:border-box} body{margin:0;font-family:system-ui,sans-serif;background:var(--bg);color:var(--fg)}
.wrap{max-width:820px;margin:0 auto;padding:24px}
h1{font-size:20px;margin:0 0 2px} .sub{color:var(--mut);font-size:13px;margin-bottom:20px}
.subbar{background:var(--card);border:1px solid #ffffff14;border-radius:12px;padding:14px;margin-bottom:18px}
.subbar b{color:var(--acc)} .subbar code{display:block;word-break:break-all;color:var(--mut);font-size:12px;margin-top:6px}
.subbar .btns{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
.cfg{background:var(--card);border:1px solid #ffffff10;border-radius:10px;padding:12px;margin-bottom:10px}
.cfg .nm{font-weight:600;font-size:13px;margin-bottom:6px}
.cfg code{display:block;word-break:break-all;color:var(--mut);font-size:11px;line-height:1.5}
button{background:#ffffff12;color:var(--fg);border:1px solid #ffffff1f;border-radius:8px;padding:7px 12px;font-size:12px;cursor:pointer}
button:hover{background:var(--acc);border-color:var(--acc);color:#000}
.cfg button{margin-top:8px}
a.b{display:inline-block;text-decoration:none}
</style>
<div class="wrap">
  <h1>⚡ ForgeEdge</h1>
  <div class="sub">Free VLESS configs over Cloudflare's clean edge. Import a subscription (auto-updates) or copy a single config.</div>
  <div class="subbar">
    <b>Subscription</b> — import once, get every config (and future updates):
    <code>${esc(subURL)}</code>
    <div class="btns">
      <button onclick='cp(${JSON.stringify(subURL)})'>copy sub</button>
      <a class="b" href="/${base}/sub/singbox"><button>sing-box</button></a>
      <a class="b" href="/${base}/sub/clash"><button>clash</button></a>
    </div>
  </div>
  <div>${rows}</div>
</div>
<script>
function cp(t){navigator.clipboard.writeText(t).then(()=>{},()=>{});}
</script>`;
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
function wsReadable(ws, earlyB64) {
  return new ReadableStream({
    start(ctrl) {
      const early = base64ToBytes(earlyB64);
      if (early && early.byteLength) ctrl.enqueue(early.buffer);
      ws.addEventListener('message', (e) => ctrl.enqueue(e.data));
      ws.addEventListener('close', () => { try { ctrl.close(); } catch (_) {} });
      ws.addEventListener('error', (e) => ctrl.error(e));
    },
    cancel() { try { ws.close(); } catch (_) {} },
  });
}
function safeClose(s) { try { s && s.close && s.close(); } catch (_) {} }
function splitHostPort(hp, def) { const i = hp.lastIndexOf(':'); return i > 0 ? [hp.slice(0, i), Number(hp.slice(i + 1)) || def] : [hp, def]; }
function base64ToBytes(s) {
  if (!s) return null;
  try { s = s.replace(/-/g, '+').replace(/_/g, '/'); const bin = atob(s); const u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; } catch (_) { return null; }
}
function bytesToUUID(b) {
  const h = []; for (let i = 0; i < 256; i++) h.push((i + 0x100).toString(16).slice(1));
  return (h[b[0]] + h[b[1]] + h[b[2]] + h[b[3]] + '-' + h[b[4]] + h[b[5]] + '-' + h[b[6]] + h[b[7]] + '-' + h[b[8]] + h[b[9]] + '-' + h[b[10]] + h[b[11]] + h[b[12]] + h[b[13]] + h[b[14]] + h[b[15]]).toLowerCase();
}
function normalizeUUID(u) { return u && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(u.trim()) ? u.trim().toLowerCase() : ''; }
// Derive a stable UUID from the Worker hostname when none is configured, so a
// fresh deploy still has a working (if guessable) id until the operator sets one.
async function deriveUUID(request) {
  const host = (request.headers.get('Host') || 'forgeedge').toLowerCase();
  const data = new TextEncoder().encode('forgeedge:' + host);
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', data));
  const b = d.slice(0, 16);
  b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80; // v4-shaped
  return bytesToUUID(b);
}
function esc(s) { return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
function html(body, status) { return new Response(body, { status, headers: { 'content-type': 'text/html;charset=utf-8' } }); }
function text(body, status) { return new Response(body, { status, headers: { 'content-type': 'text/plain;charset=utf-8' } }); }
function json(obj, status) { return new Response(JSON.stringify(obj, null, 2), { status, headers: { 'content-type': 'application/json;charset=utf-8' } }); }
