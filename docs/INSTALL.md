# Installing ForgePanel

Every release publishes static Linux binaries and native Debian/RPM packages
from the same commit and test run. The Dockerfile builds the same application
from a pinned release tag and uses the same database schema, migrations, and
first-run setup flow.

## One command (Linux, systemd)

The installer is published as a release asset **alongside its SHA-256
checksum**. Fetch the pinned copy for the release you want and verify it before
running it as root:

```bash
VERSION=v1.5.8
curl -fsSLO https://github.com/paranoideveloper/forgepanel/releases/download/$VERSION/install.sh
curl -fsSLO https://github.com/paranoideveloper/forgepanel/releases/download/$VERSION/install.sh.sha256
sha256sum -c install.sh.sha256 && sudo bash install.sh
```

This is deliberately two steps rather than a one-line pipe into a root shell.
The pipeline goes to the trouble of producing checksums, SBOMs and signatures;
it should not then ask you to run an unverified script from a branch that can
change under you. Piping from `main` also means you cannot reproduce later what
you actually ran.

The installer downloads the release binary, creates a hardened `forgepanel`
systemd unit, opens the firewall ports it needs, starts the service, and prints
your **panel URL** and a **one-time setup token**. Open the URL and create your
administrator account with that token — no password is generated for you. The
token is single-use and expires on a timer, so a host that is reachable before
you finish setup cannot be claimed by someone else.

Useful installer flags: `--update`/`--repair`, `--dry-run`, `--uninstall`,
`--uninstall --purge`, and `--tui` (full-screen dialog UI instead of plain
prompts). The installer verifies every release binary against the release
checksum before stopping the existing service, writes new binaries and unit
files atomically, validates the service, and restores its recorded prior files
if validation fails.

## Local host management

On a systemd host, run `sudo forgectl` with no arguments for the interactive
menu. The same operations are scriptable:

```bash
sudo forgectl status --json
sudo forgectl service restart
sudo forgectl settings set --panel-port 8443
sudo forgectl dns-check panel.example.com
sudo forgectl cert status
sudo forgectl backup create /root/forgepanel-backup.enc
sudo forgectl update --check
sudo forgectl update --yes
```

Backups are encrypted with the installed panel's master key. The key is read
locally from `secrets.json`; no backup or restore command accepts a secret on
its command line.

## Uninstall and recovery

Every verified installer and package installation writes
`/etc/forgepanel/install-manifest.json` with the exact files, original backups,
systemd changes and ForgePanel-owned firewall markers. `forgectl uninstall`
stops only the ForgePanel service cgroup, removes only manifest-proven files,
and removes only rules in the `forgepanel_porthop` nftables table or rules with
the `forgepanel-porthop-` comment. It never flushes a firewall table.

```bash
sudo forgectl uninstall                 # preserve data, secrets and certificates
sudo forgectl uninstall --dry-run       # show the exact actions
sudo forgectl uninstall --purge --yes   # remove manifest-owned data too
sudo forgectl repair                    # reload/enable/restart a recorded install
```

Changed files and legacy installations are retained and reported rather than
deleted by guesswork. Keep the manifest when preserving data; it is needed for
later repair or explicit purge.

## Docker

```bash
VERSION=v1.5.8
git clone --depth 1 --branch "$VERSION" https://github.com/paranoideveloper/forgepanel.git
cd forgepanel
FORGEPANEL_VERSION=$VERSION docker compose up -d --build
```

The checked-in Compose file builds a local image tagged with
`FORGEPANEL_VERSION`. Pin the Git checkout and that variable to the same release
tag; a production update is then an explicit checkout and rebuild, never an
implicit floating-image pull.

### What the container needs

- **Data volume**: `/var/lib/forgepanel` holds the SQLite database, secrets and
  certificates. `docker compose down` keeps it; only `down -v` discards it.
- **Ports**: `2053` panel, `2054` REST API, `2096` subscriptions. Publish `80`
  and `443` only if you serve the panel on a domain with an automatic
  certificate — `80` answers the ACME challenge and `443` serves the panel
  afterwards. Publish `53/udp` only if you run ForgeDNS. Proxy inbounds you
  create in the panel listen inside the container, so each needs its port
  published too.
- **User and capabilities**: the image runs as a **non-root** user (uid 65532).
  It carries `CAP_NET_BIND_SERVICE` on the binary, the single capability that
  allows binding ports below 1024 — that is how it serves 80/443/53 without
  being root. Nothing needs privileged mode. Add `--cap-add=NET_ADMIN` **only**
  for hysteria2 port-hopping or some ForgeDNS setups, both of which reprogram
  host networking; without it the panel runs normally and those specific
  features report an error rather than failing quietly.
- **Signals**: the panel is PID 1 and handles `SIGTERM`, so `docker stop` shuts
  the engines down cleanly.

### Verifying a local image

```bash
docker image inspect forgepanel:v1.5.8
docker run --rm --entrypoint /usr/local/bin/forgectl forgepanel:v1.5.8 version
```

## From source

```bash
make build
./bin/forgepanel --version
./bin/forgepanel            # first boot prints the panel URL + setup token
```

A source build reports its version as `dev`. That is deliberate: only the
release pipeline stamps a real version, so a hand-built binary can never claim
to be a release it is not.

## Moving between systemd and Docker

Both installations use the same data directory layout, the same schema and the
same settings, so migrating is a copy plus an ownership fix.

**systemd → Docker**

```bash
sudo systemctl stop forgepanel
docker volume create forgepanel-data
sudo tar -C /var/lib/forgepanel -cf - . \
  | docker run --rm -i -v forgepanel-data:/data alpine tar -C /data -xf -
docker run --rm -v forgepanel-data:/data alpine chown -R 65532:65532 /data
docker compose up -d
sudo systemctl disable forgepanel
```

**Docker → systemd**

```bash
docker compose down
docker run --rm -v forgepanel-data:/data alpine tar -C /data -cf - . \
  | sudo tar -C /var/lib/forgepanel -xf -
sudo chown -R forgepanel:forgepanel /var/lib/forgepanel
sudo systemctl enable --now forgepanel
```

The ownership step matters in both directions: the container runs as uid 65532
and the systemd unit as the `forgepanel` user, and a data directory the process
cannot write is the most common way one of these migrations fails.

**Stop the old one first.** The panel takes an exclusive lock on its data
directory, and a second instance refuses to start, naming the process that holds
it. That check exists because two panels sharing one SQLite file fight over
engine processes, listening ports and traffic counters, and the resulting
accounting corruption is very hard to attribute afterwards.

## First boot

The server prints a randomized admin path (`/panel/<random>`) and a one-time
setup token. Open the panel URL and create your administrator account with the
token; you choose the password. No admin password is ever generated or printed.
