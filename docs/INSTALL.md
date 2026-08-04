# Installing ForgePanel

## One-command (Linux)
```
curl -fsSL https://example/install.sh | bash        # or: sudo bash deploy/install.sh
```
Installs the binary + a hardened systemd unit, opens firewall ports, and prints
the admin credentials **once**. Flags: `--uninstall`, `--update`.

## Docker
```
docker compose up -d        # SQLite by default
```
Data persists in the `forgepanel-data` volume. The panel is on `:2053`,
subscriptions on `:2096`, ForgeDNS on `:53/udp`.

## From source
```
make GO=/path/to/go1.24 build
./bin/forgepanel            # first boot prints the admin path + password
```

## First boot
The server prints a randomized admin path (`/panel/<random>`) and a generated
admin password **once** — save them. Open the panel URL and sign in.
