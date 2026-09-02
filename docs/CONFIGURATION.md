# Configuration

On a host installation, `<data>/panel.json` is the authoritative, atomically
written source for the panel address, domain, HTTPS and ACME settings. Change it
through the authenticated web UI or the root-only local command:

```bash
sudo forgectl settings show
sudo forgectl settings set --panel-port 8443
sudo forgectl settings set --domain panel.example.com --https=true --acme-email ops@example.com --verify-dns
```

The systemd environment file is intentionally limited to `FORGEPANEL_DATA` for
a non-default data directory. Legacy address environment variables are read only
when creating a previously missing `panel.json`; they never override a saved
setting on restart or upgrade.

| Bootstrap/runtime variable | Default | Purpose |
|---|---|---|
| `FORGEPANEL_DATA` | `~/.forgepanel` | data + secrets directory (mode 0700) |
| `FORGEPANEL_SUB_PORT` | `2096` | subscription listener port |
| `FORGEPANEL_API_PORT` | `2054` | REST API listener port |
| `FORGEPANEL_DNS_PORT` | `53` | ForgeDNS authoritative listener port |
| `FORGEPANEL_ADMIN_USER` | `admin` | initial administrator username |
| `FORGEPANEL_TELEGRAM_TOKEN` | — | Telegram bot token (from @BotFather); enables the bot |
| `FORGEPANEL_TELEGRAM_ADMINS` | — | comma-separated Telegram chat IDs allowed to run admin commands |

## Telegram bot

Run the whole panel from a Telegram chat. **Setup (three steps, ~1 minute):**

1. **Create the bot.** In Telegram, message [@BotFather](https://t.me/BotFather),
   send `/newbot`, follow the prompts, and copy the token it gives you
   (looks like `123456789:AA…`).
2. **Get your chat id.** Message [@userinfobot](https://t.me/userinfobot); it
   replies with your numeric `Id`. That id is an admin.
3. **Enable it.** Add the two lines to `/etc/forgepanel/forgepanel.env` (the
   installer leaves them commented there ready to fill in), then restart:

   ```sh
   # /etc/forgepanel/forgepanel.env
   FORGEPANEL_TELEGRAM_TOKEN=123456789:AA-your-bot-token
   FORGEPANEL_TELEGRAM_ADMINS=11111111,22222222   # comma-separated admin chat ids
   ```
   ```sh
   sudo systemctl restart forgepanel
   ```

The bot starts automatically on boot whenever a token is set (there is nothing to
install separately — it is built into the panel binary). Any user can run
`/sub <token>` to get their subscription link and `/help`. Admins (the chat IDs
above) additionally get:

| Command | Action |
|---|---|
| `/stats` | inbound / user / group counts |
| `/user <name>` | status + traffic |
| `/adduser <name>` | create a user (returns its sub token) |
| `/deluser <name>` | delete a user |
| `/enable <name>` · `/disable <name>` | cut a user off / restore |
| `/reset <name>` | zero traffic (lifts an over-quota cap) |
| `/limit <name> <GB>` | set the data cap (0 = unlimited) |
| `/extend <name> <days>` | extend expiry |

Every mutation reloads the running cores immediately, so a disabled or deleted
user stops being served at once — the same behaviour as an edit from the web panel.

Secrets (master key and compatibility metadata) are generated on first boot in
`<data>/secrets.json` and never leave the machine. The master key derives the
JWT signing secret and backup-encryption key. The SQLite database is
`<data>/forgepanel.db`; engine binaries are pinned under `<data>/bin/` on first
use.

---

## Users, groups and inbound assignment

A user's access to inbounds comes from two independent places, and the panel
keeps them distinct rather than flattening them into one list:

| | Where it comes from | Who can change it |
|---|---|---|
| **Direct** | assigned to this user specifically | edit the user |
| **Inherited** | the user's group | edit the group — affects every member |
| **Effective** | the union of the two | what subscriptions and engine configs use |

The distinction is the point. "Remove this inbound" means something different
for each: a direct assignment is the user's own and can be dropped on their edit
screen, while an inherited one belongs to the group, so the panel shows it
read-only there and sends you to the group — where the change is applied to
everybody in it, with a confirmation that says how many people that is.

**A user does not need a group.** "No group" is a valid, persistent state, not a
missing value. Such a user keeps whatever is assigned to them directly. The
create form offers it explicitly and never silently picks a group for you: the
only group pre-selected is one you marked as the default, and a default is a
pre-selection in the form, visible before you save, never something applied
behind your back. Nothing in the panel creates a group as a side effect.

### Editing

Every field on a user and a group can be corrected after creation. Two
guarantees are worth stating outright:

- **Editing never rotates credentials.** Changing a note, quota or expiry leaves
  the UUID, password and subscription token exactly as they were. Rotating the
  subscription token invalidates every client already configured with the
  account, so it lives behind its own explicit action with its own confirmation.
- **Concurrent edits do not silently clobber each other.** The edit form sends
  back the `updated_at` it read; if someone else changed the record in the
  meantime the write is refused with `409` and you are asked to reload, instead
  of the later save quietly overwriting the earlier one.

Field permissions are enforced on the server with an explicit allowlist per
role, and a request carrying a field the caller may not change is **rejected**,
not quietly ignored — a silent drop would report success for an edit that never
happened. Resellers can edit their own users' names, status, notes, expiry and
group, but not quota-shaped fields: raising a user's data limit would let a
reseller mint traffic they were never allocated. Every object id in a request —
user, group, inbound — is checked against the caller's scope in the repository
layer, not merely hidden from the UI.

### Deleting a group never deletes users

Deleting a group with members requires you to say what happens to them: move
them to another group, or leave them with no group. There is no path that
removes an account as a side effect of removing its group. Members left without
a group keep their direct assignments and lose the ones the group granted.

## The status indicator

The topbar indicator reports the worst state across six subsystems: the panel
API, the database, the local proxy engine, remote nodes, certificates and
ForgeDNS. Clicking it (or focusing it and pressing Enter) opens a panel with one
row per subsystem giving its state, a plain-language summary and, where relevant,
the specifics — which engine failed and why, how many nodes are stale, how many
certificates expire soon.

Two rules it follows:

- **Colour is never the only signal.** The state is spelled out in words next to
  the dot and in the element's accessible name, so it is legible in monochrome,
  to screen readers, and to anyone with a colour-vision deficiency.
- **"Not configured" is not a fault.** A panel with no inbounds yet, no enrolled
  nodes, or no DNS zones is working correctly and says so. It previously showed
  red in exactly those cases, which is how an indicator teaches people to ignore
  it.

## Contextual help

Settings that are not self-explanatory carry a small **i** next to their label.
It responds to click, Enter and Space — never hover alone, which touch and
keyboard users cannot reach — closes on Escape or an outside click, and is
positioned to stay on screen. Content lives in one registry in the admin page
rather than being scattered through the views, so wording stays consistent and
is translatable in one place; entries that warrant more detail link into these
documents.
