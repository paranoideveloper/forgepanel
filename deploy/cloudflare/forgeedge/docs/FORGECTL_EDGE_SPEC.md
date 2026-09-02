# `forgectl edge` — CLI specification

The Go implementation of these commands is **not** written (the ForgeEdge brief
forbade touching Go). This is the exact contract to implement, with every
payload and every failure mode already exercised against the Worker.

Suggested location: `cmd/forgectl/edge.go` + `internal/edge/`.

---

## Credential policy

Two paths, and they are **not** equivalent. State the difference in `--help`,
because operators reasonably assume a stored token is as safe as an OAuth
session and it is not.

### OAuth + PKCE — the default

No long-lived secret is ever written anywhere. Cloudflare's own dashboard flow
issues a token to the operator's machine; the Worker never sees it.

```
client_id      54d11594-84e4-41aa-b438-e81b8fa78ee7   (Wrangler's public client)
authorize      https://dash.cloudflare.com/oauth2/auth
token          https://dash.cloudflare.com/oauth2/token
redirect_uri   http://localhost:<ephemeral>/oauth/callback
scopes         account:read user:read workers:write workers_kv:write
               workers_scripts:write d1:write pages:write pages:read zone:read
               offline_access
challenge      S256 over a 43+ char verifier
```

Flow:

1. Generate `state` (32 random bytes, base64url) and `code_verifier` (33 random
   bytes, base64url).
2. Bind a listener on `127.0.0.1:0`; use the assigned port in `redirect_uri`.
3. Open the authorize URL (`xdg-open`/`open`/`rundll32`, and always print it —
   headless boxes and Termux have no browser).
4. On callback: reject a mismatched `state` **before** touching `code`.
5. Exchange for a token; store the refresh token in the OS keyring, falling back
   to `~/.config/forgepanel/edge-token.json` at mode `0600`.
6. `GET /accounts` to resolve the account id; prompt when there is more than one.

### `--api-token` — the fallback

For CI, for accounts where the OAuth client is unavailable, and for operators who
want the panel itself to self-update. Mint at
`https://dash.cloudflare.com/profile/api-tokens` with:

| Permission | Level |
|---|---|
| Workers Scripts | Edit |
| Workers KV Storage | Edit |
| Workers R2 (only if used) | Edit |
| Pages | Edit |
| DNS | Edit *(only for `--domain`)* |
| Account Settings | Read |
| User Details | Read |

`forgectl edge token-url` should print a pre-filled
`https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=[…]&accountId=*&zoneId=all&name=ForgePanel-Edge`
so nobody has to click through the permission matrix by hand.

> A token passed as `--api-token` is used for that invocation only. A token
> written into the Worker (the `CF_API_TOKEN` binding) is readable by anyone who
> can deploy to that account — only do it if the panel must self-manage, and say
> so at the prompt.

---

## `forgectl edge deploy`

```
forgectl edge deploy [flags]

  --name string        Worker/Pages project name       (default: forgeedge-<6 hex>)
  --target string      workers | pages                 (default: workers)
  --domain string      custom domain to attach (needs the zone in this account)
  --api-token string   skip OAuth and use this token
  --account string     account id, when the token spans several
  --backend string     ForgePanel node WS URL; turns Backend Mode on
  --feed               push the canonical feed immediately after deploy
  --json               machine-readable output
```

Steps:

1. Authorise (OAuth, or `--api-token`).
2. `GET /accounts/{id}/workers/scripts/{name}` → refuse if it exists, unless
   `--force`. Silently overwriting someone's Worker is not acceptable.
3. Create the KV namespace: `POST /accounts/{id}/storage/kv/namespaces`
   `{"title": "<name>-forgeedge"}` → keep `result.id`.
4. Optionally create D1: `POST /accounts/{id}/d1/database` `{"name": "<name>"}`.
5. Build the bundle (`bun run build` in `deploy/cloudflare/forgeedge`, or ship a
   release artifact).
6. Upload:

   ```
   PUT /accounts/{id}/workers/scripts/{name}
   Content-Type: multipart/form-data

   metadata = {
     "main_module": "worker.js",
     "compatibility_date": "<today>",
     "compatibility_flags": ["nodejs_compat"],
     "keep_bindings": ["kv_namespace", "d1"],
     "bindings": [
       {"type": "kv_namespace", "name": "KV", "namespace_id": "<kv id>"}
       // {"type": "d1", "name": "DB", "id": "<d1 id>"}   // when --d1
     ]
   }
   worker.js = <bundle>   (application/javascript+module)
   ```

   `keep_bindings` is not optional: without it an update detaches KV and every
   subscriber's config disappears on the next request.

7. Enable the subdomain:
   `POST /accounts/{id}/workers/scripts/{name}/subdomain` `{"enabled": true}`.
   If the account has no `workers.dev` subdomain yet,
   `PUT /accounts/{id}/workers/subdomain` `{"subdomain": "<random>"}` first.
8. `--domain`: find the zone by TLD, then
   `PUT /accounts/{id}/workers/domains` `{hostname, service, environment:"production", zone_id}`.
   For Pages: `POST /accounts/{id}/pages/projects/{name}/domains` **and** a
   proxied CNAME.
9. **Read back the secure path.** The Worker mints it on its first request, so:

   ```
   GET https://<name>.<subdomain>.workers.dev/
   ```

   (any request boots it), then read the Worker log line
   `[forgeedge] bootstrapped. Panel: /<path>/panel`, via
   `GET /accounts/{id}/workers/scripts/{name}/tails`.

   **Simpler and preferred:** pass the path in yourself before deploying, by
   setting the `SECURE_PATH` var in `metadata.bindings` as
   `{"type":"plain_text","name":"SECURE_PATH","text":"<24 chars a-z2-9>"}`. Then
   `forgectl` already knows it and never has to scrape a log. Generate it with
   the same alphabet the Worker uses (`a-z` minus `l`/`o`, digits `2-9`).

10. Register the deployment in the panel DB (see `GO_WIRING.md` §2.3), reading
    `feedPushToken` from `GET /<path>/api/status` after the first login.
11. `--feed`: push the canonical feed.

Output:

```
ForgeEdge deployed.
  Worker        forgeedge-a1b2c3
  URL           https://forgeedge-a1b2c3.acme.workers.dev
  Panel         https://forgeedge-a1b2c3.acme.workers.dev/<path>/panel
  Subscription  https://forgeedge-a1b2c3.acme.workers.dev/<path>/sub/<sub_token>
  DoH           https://forgeedge-a1b2c3.acme.workers.dev/<path>/dns-query
  Backend mode  off  (edge terminates VLESS/Trojan over WS; TCP only, DNS-over-UDP only)

Set an admin password at the panel URL before sharing anything.
```

---

## `forgectl edge update`

```
forgectl edge update [--name string] [--all] [--check-only]
```

- `--check-only`: `GET https://api.github.com/repos/<repo>/releases/latest`,
  compare to `GET /<path>/api/status` → `body.version`, print, exit.
- Otherwise: rebuild and re-`PUT` the script. `keep_bindings` preserves KV/D1, so
  config, users and the secure path survive.
- Refuse a downgrade unless `--force`.
- After the upload, poll `GET /<path>/api/status` until `version` matches, with a
  30s deadline, and report a rollback command if it does not.

ForgeEdge does **not** update itself at runtime. A Worker that fetches and
executes remote code is a supply-chain compromise with extra steps, and it robs
the operator of the chance to read the diff. The Worker's cron only *reports*
that a release exists.

---

## `forgectl edge delete`

```
forgectl edge delete --name string [--yes] [--keep-kv]
```

1. Confirm interactively unless `--yes`; print the URL being destroyed.
2. `DELETE /accounts/{id}/workers/scripts/{name}` (or the Pages project).
3. Unless `--keep-kv`: `DELETE /accounts/{id}/storage/kv/namespaces/{kv}` and the
   D1 database.
4. Remove the row from `edge_deployments`.

Every subscription URL served by that Worker dies immediately. Say so at the
prompt, with the user count from the last feed.

---

## `forgectl edge status`

```
forgectl edge status [--name string] [--all] [--json]
```

Merges the Cloudflare view with the Worker's own:

```
forgeedge-a1b2c3      workers    https://forgeedge-a1b2c3.acme.workers.dev
  deployed      2026-08-07T09:14:22Z         version 0.1.0
  bindings      KV ok, D1 absent
  users         14 (feed generated 2026-08-07T09:10:00Z, pushed 4m ago)
  backend       wss://node1.example.com/forgeedge   reachable
  clean IPs     37 (refreshed 2026-08-07T06:17:00Z)
  secure path   rotated 2026-08-01T12:00:00Z
  update        0.1.0 is current
```

Sources: `GET /accounts/{id}/workers/scripts/{name}` (existence, modified date),
`GET /accounts/{id}/workers/domains?service={name}` (hostnames), and
`GET /<path>/api/status` with the session cookie (everything else).

---

## `forgectl edge push`

```
forgectl edge push [--name string] [--all] [--dry-run]
```

```
POST https://<worker>/<path>/feed
Authorization: Bearer <feedPushToken>
Content-Type: application/json

{ …the canonical feed from GO_WIRING.md §2.1… }
```

Response:

```json
{"success":true,"status":200,"message":"Feed accepted.",
 "body":{"users":14,"sharedNodes":2,"warnings":[]}}
```

**Always surface `warnings`.** A non-empty array means the edge dropped users or
nodes it could not parse, and those subscribers are getting a short list without
knowing it.

`--dry-run` prints the document and the node count per user without sending.

---

## `forgectl edge rotate-path`

```
forgectl edge rotate-path --name string [--yes]
```

`POST /<path>/api/rotate-path` with the admin session. Every previous URL —
panel, API, **and every subscription** — stops working immediately, and the
admin session is invalidated. Requires an explicit confirmation and should be
followed by a re-push of the subscriptions to users.

---

## Telegram deploy path

The bot in `src/telegram/bot.ts` deliberately does **not** deploy. Deploying
needs a Cloudflare credential, and gating that behind a chat authorisation check
means one wrong `telegramUserID` hands over the account.

What it does: `/status`, `/panel`, `/subs`, `/rotate`, `/help` — all owner-only,
checked before anything is read from the message.

For a phone-only install, the supported shape is:

1. The operator runs `forgectl edge deploy` **once**, anywhere (the OAuth flow
   needs a browser).
2. `forgectl` sets `telegramBotToken` + `telegramUserID` in the Worker config and
   registers the webhook:
   `POST https://api.telegram.org/bot<token>/setWebhook`
   `{"url": "https://<worker>/<path>/telegram", "allowed_updates": ["message"]}`.
3. Everything afterwards — status, subscription URLs, rotation — is reachable
   from the phone.

If a fully phone-native install is wanted later, the honest design is a
ForgePanel-hosted OAuth relay: the bot sends a one-time link, the operator
completes Cloudflare's OAuth in their phone browser, and the token stays on the
panel server. That is a panel feature, not a Worker feature, and it should not be
built by pasting API tokens into a chat.

---

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | generic failure |
| 2 | usage error |
| 3 | authorisation failed / token rejected |
| 4 | name already taken (deploy without `--force`) |
| 5 | Worker not found (update/delete/status) |
| 6 | feed rejected by the edge (see `warnings`) |
