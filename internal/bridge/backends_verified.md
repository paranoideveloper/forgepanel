# Bridge backends — what was actually checked, and how

Every claim in `backends.go` and every template in `render.go` was run against
the real binary on **2026-08-26**, on linux/amd64. This file records the
commands so the next person can re-run them instead of trusting a comment.

Nothing here was taken from a README or from memory. The reason is the failure
mode: a reverse tunnel that starts with a subtly wrong config does not crash —
it comes up, reports healthy, and moves no traffic. Nobody notices until users
say the server is down, and the panel is showing green.

## Versions pinned

| backend  | version  | asset                                        |
|----------|----------|----------------------------------------------|
| backhaul | v0.7.2   | `backhaul_linux_amd64.tar.gz`                |
| rathole  | v0.5.0   | `rathole-x86_64-unknown-linux-gnu.zip`       |
| frp      | v0.71.0  | `frp_0.71.0_linux_amd64.tar.gz`              |
| wstunnel | v10.6.2  | `wstunnel_10.6.2_linux_amd64.tar.gz`         |

**rathole moved orgs.** `rapiz1/rathole` 301-redirects to `rathole-org/rathole`.
Following the redirect silently works until it stops, so the descriptor names
the current home.

## UDP — the property that decides whether Hysteria2 survives

A bridge that carries only TCP silently drops Hysteria2, TUIC and WireGuard
while every dashboard stays green. All four were checked:

| backend  | how UDP was proven |
|----------|--------------------|
| backhaul | `transport = "udp"` config started clean (exit 124 = still running at the timeout) |
| rathole  | `[server.services.x] type = "udp"` accepted and listening |
| frp      | `frpc verify -c` passed a `[[proxies]] type = "udp"` |
| wstunnel | `-L udp://…` is in the binary's own `--help`; the client logged `Starting UDP server listening cnx on 127.0.0.1:38081` |

## The validators are real — a bad config IS rejected

Checking that a good config is accepted proves nothing on its own if the tool
accepts anything. Each was given a deliberately wrong config:

```
$ ./backhaul -c bad.toml        # [nonsense] only
exit=1  FATAL neither server nor client configuration is properly set.

$ ./rathole -s bad.toml         # unknown key
exit=1  Error: Configuration is invalid.

$ ./rathole -s bad2.toml        # bind_addr = "not-an-address"
exit=1  Error: Configuration is invalid.
```

rathole is the strictest: it rejects an *unknown key* rather than ignoring it,
so a typo fails loudly at start rather than silently disabling a service.

## The rendered configs were accepted

Rendered from `Render()` with two services (one udp, one tcp) and fed straight
to each binary:

```
$ frps verify -c frp_exit.toml      → syntax is ok
$ frpc verify -c frp_bridge.toml    → syntax is ok
$ rathole -s rathole_exit.toml      → INFO rathole::server: Listening at 0.0.0.0:38443
$ rathole -c rathole_bridge.toml    → INFO handle{service=reality}: rathole::client: Starting …
$ backhaul -c backhaul_exit.toml    → no FATAL/ERROR
$ backhaul -c backhaul_bridge.toml  → no FATAL/ERROR
$ wstunnel server ws://0.0.0.0:38443 --restrict-http-upgrade-path-prefix <token>   → running
$ wstunnel client -L udp://… -L tcp://… --http-upgrade-path-prefix <token> ws://…  → running, UDP listener up
```

Those exact bytes are the golden expectations in `render_test.go`, so a change
to a template that the tool would reject fails in CI rather than on a bridge
nobody can reach to debug.

## Operational surprise worth knowing

**backhaul mutates host sysctls on start.** Its own log:

```
INFO Applying TCP optimizations for Linux...
INFO Successfully set rmem_max to 268435456
```

That changes networking for everything else on the machine, not just the
tunnel. `Backend.MutatesSysctl` carries it so the panel can say so before an
operator installs it on a box doing other work.

## frp is the only one that can check without starting

`frps verify -c` / `frpc verify -c`. The other three validate by starting, which
is why `Backend.VerifyArgs` is empty for them rather than guessed.
