// ForgePanel subscription-mirror Cloudflare Worker (spec §7 CDN mode). Deploy and
// point users at the worker URL so subscription links survive origin blocking.
// Set ORIGIN to your panel's sub endpoint, e.g. https://panel.example.com
const ORIGIN = "https://REPLACE-WITH-YOUR-PANEL";
export default {
  async fetch(req) {
    const url = new URL(req.url);
    const target = ORIGIN + url.pathname + url.search;
    const resp = await fetch(target, { headers: { "User-Agent": req.headers.get("User-Agent") || "" } });
    const h = new Headers(resp.headers);
    h.set("Access-Control-Allow-Origin", "*");
    return new Response(resp.body, { status: resp.status, headers: h });
  },
};
