#!/usr/bin/env bash
#
# ForgePanel — installer & first-run setup wizard.
#
#   curl -fsSL https://raw.githubusercontent.com/paranoideveloper/forgepanel/main/install.sh | sudo bash
#
# The wizard walks you through port / domain / HTTPS selection, installs the
# release binary, registers a systemd service and prints your one-time setup
# token so you can create the admin account from the browser.
#
# Non-interactive use (CI, cloud-init, no TTY) is fully supported — every answer
# can be supplied up-front through flags or environment variables:
#
#   FORGEPANEL_ASSUME_YES=1 FORGEPANEL_PANEL_PORT=8443 \
#   FORGEPANEL_DOMAIN=panel.example.com FORGEPANEL_ACME_EMAIL=me@example.com \
#   bash install.sh
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
REPO="paranoideveloper/forgepanel"
SERVICE="forgepanel"
BIN_PATH="/usr/local/bin/forgepanel"
CTL_PATH="/usr/local/bin/forgectl"
NODE_PATH="/usr/local/bin/forgenode"
UNIT_PATH="/etc/systemd/system/forgepanel.service"
ENV_DIR="/etc/forgepanel"
ENV_FILE="${ENV_DIR}/forgepanel.env"
MANIFEST_PATH="${ENV_DIR}/install-manifest.json"
DEFAULT_DATA="/var/lib/forgepanel"
DEFAULT_PORT="2053"
TITLE="ForgePanel Setup"
TOTAL_STEPS=7

# ---------------------------------------------------------------------------
# Settings (env vars are the defaults; flags and the wizard override them)
# ---------------------------------------------------------------------------
DATA_DIR="${FORGEPANEL_DATA:-$DEFAULT_DATA}"
PANEL_PORT="${FORGEPANEL_PANEL_PORT:-}"
PANEL_DOMAIN="${FORGEPANEL_DOMAIN:-}"
PANEL_HTTPS="${FORGEPANEL_HTTPS:-}"
ACME_EMAIL="${FORGEPANEL_ACME_EMAIL:-}"
VERSION="${FORGEPANEL_VERSION:-}"
ASSUME_YES="${FORGEPANEL_ASSUME_YES:-0}"
UI_PREF="${FORGEPANEL_UI:-auto}"
DO_UNINSTALL=0
DO_PURGE=0
DRY_RUN=0
REPAIR=0
HTTPS_FORCED=""
PANEL_CONFIG_EXISTS=0
PORT_EXPLICIT=0
DOMAIN_EXPLICIT=0
EMAIL_EXPLICIT=0
HTTPS_EXPLICIT=0

[[ -n "${FORGEPANEL_PANEL_PORT+x}" ]] && PORT_EXPLICIT=1
[[ -n "${FORGEPANEL_DOMAIN+x}" ]] && DOMAIN_EXPLICIT=1
[[ -n "${FORGEPANEL_ACME_EMAIL+x}" ]] && EMAIL_EXPLICIT=1
[[ -n "${FORGEPANEL_HTTPS+x}" ]] && HTTPS_EXPLICIT=1

# Runtime state
ARCH=""
OS_NAME="Linux"
OS_PRETTY=""
IPV4=""
IPV6=""
SERVER_IP=""
INTERACTIVE=0
UI="plain"
UPGRADE=0
PREV_PORT=""

# ---------------------------------------------------------------------------
# Presentation helpers
# ---------------------------------------------------------------------------
if [[ -t 1 && -z "${NO_COLOR:-}" && "${TERM:-dumb}" != "dumb" ]]; then
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
  C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'; C_CYAN=$'\033[36m'; C_MAGENTA=$'\033[35m'
else
  C_RESET=""; C_BOLD=""; C_DIM=""
  C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_CYAN=""; C_MAGENTA=""
fi

if [[ "${LANG:-}${LC_ALL:-}${LC_CTYPE:-}" == *[Uu][Tt][Ff]* ]]; then
  RULE_CHAR="─"; TICK="✔"; CROSS="✘"; BULLET="•"; ARROW="›"
else
  RULE_CHAR="-"; TICK="+"; CROSS="x"; BULLET="*"; ARROW=">"
fi

RULE_WIDTH=66

rule() {
  local color="${1:-$C_DIM}" i line=""
  for ((i = 0; i < RULE_WIDTH; i++)); do line+="$RULE_CHAR"; done
  printf '%s%s%s\n' "$color" "$line" "$C_RESET"
}

banner() {
  printf '\n'
  rule "$C_CYAN"
  printf '%s   F O R G E P A N E L%s   %sinstaller & setup wizard%s\n' \
    "$C_BOLD$C_CYAN" "$C_RESET" "$C_DIM" "$C_RESET"
  rule "$C_CYAN"
  printf '\n'
}

step() {
  local n="$1" text="$2"
  printf '\n%s%s[%s/%s]%s %s%s%s\n' \
    "$C_BOLD" "$C_BLUE" "$n" "$TOTAL_STEPS" "$C_RESET" "$C_BOLD" "$text" "$C_RESET"
}

info() { printf '   %s%s%s %s\n' "$C_DIM" "$BULLET" "$C_RESET" "$*"; }
ok()   { printf '   %s%s%s %s\n' "$C_GREEN" "$TICK" "$C_RESET" "$*"; }
warn() { printf '   %s%s warning:%s %s\n' "$C_YELLOW" "$CROSS" "$C_RESET" "$*" >&2; }
err()  { printf '\n%s%s error:%s %s\n' "$C_RED" "$CROSS" "$C_RESET" "$*" >&2; }
die()  { err "$*"; printf '\n'; exit 1; }

kv() { printf '   %s%-16s%s %s\n' "$C_DIM" "$1" "$C_RESET" "$2"; }

usage() {
  cat <<'USAGE'
ForgePanel installer

Usage:
  install.sh [options]

Options:
  -y, --yes              Accept defaults, never prompt (implied when no TTY)
      --tui              Use a full-screen dialog UI (gum/whiptail) if available
      --port <n>         Panel port (default 2053)
      --domain <host>    Panel domain; enables auto-HTTPS
      --email <addr>     Contact e-mail for certificate issuance
      --https            Force auto-HTTPS on
      --no-https         Force auto-HTTPS off
      --data <dir>       Data directory (default /var/lib/forgepanel)
      --version <tag>    Install a specific release tag instead of the latest
      --update           Alias for --repair; update verified release assets
      --repair           Reinstall matching binaries and repair the service
      --dry-run          Print the installation plan without modifying the host
      --plain            Use plain text prompts (skip gum/whiptail/dialog)
      --uninstall        Remove manifest-owned resources and preserve data
      --purge            With --uninstall, also remove manifest-owned data
  -h, --help             Show this help

Environment variables (same meaning as the flags):
  FORGEPANEL_PANEL_PORT  FORGEPANEL_DOMAIN     FORGEPANEL_HTTPS
  FORGEPANEL_ACME_EMAIL  FORGEPANEL_DATA       FORGEPANEL_VERSION
  FORGEPANEL_ASSUME_YES  FORGEPANEL_UI
USAGE
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -y|--yes)     ASSUME_YES=1; shift ;;
      --port)       PANEL_PORT="${2:-}"; PORT_EXPLICIT=1; shift 2 ;;
      --port=*)     PANEL_PORT="${1#*=}"; PORT_EXPLICIT=1; shift ;;
      --domain)     PANEL_DOMAIN="${2:-}"; DOMAIN_EXPLICIT=1; shift 2 ;;
      --domain=*)   PANEL_DOMAIN="${1#*=}"; DOMAIN_EXPLICIT=1; shift ;;
      --email)      ACME_EMAIL="${2:-}"; EMAIL_EXPLICIT=1; shift 2 ;;
      --email=*)    ACME_EMAIL="${1#*=}"; EMAIL_EXPLICIT=1; shift ;;
      --https)      HTTPS_FORCED=1; HTTPS_EXPLICIT=1; shift ;;
      --no-https)   HTTPS_FORCED=0; HTTPS_EXPLICIT=1; shift ;;
      --data)       DATA_DIR="${2:-}"; shift 2 ;;
      --data=*)     DATA_DIR="${1#*=}"; shift ;;
      --version)    VERSION="${2:-}"; shift 2 ;;
      --version=*)  VERSION="${1#*=}"; shift ;;
      --repair)     REPAIR=1; shift ;;
      --update)     REPAIR=1; shift ;;
      --dry-run)    DRY_RUN=1; shift ;;
      --plain)      UI_PREF="plain"; shift ;;
      --tui)        UI_PREF="tui"; shift ;;
      --uninstall)  DO_UNINSTALL=1; shift ;;
      --purge)      DO_PURGE=1; shift ;;
      -h|--help)    usage; exit 0 ;;
      *)            usage >&2; die "Unknown option: $1" ;;
    esac
  done
}

# ---------------------------------------------------------------------------
# TTY / UI detection
# ---------------------------------------------------------------------------
detect_ui() {
  # A controlling terminal is required for prompting. When the script is piped
  # (curl | bash) stdin is the script itself, so we always talk to /dev/tty.
  if (exec 3<>/dev/tty) 2>/dev/null; then
    INTERACTIVE=1
  else
    INTERACTIVE=0
  fi
  [[ "$ASSUME_YES" == "1" ]] && INTERACTIVE=0

  if [[ "$INTERACTIVE" != "1" ]]; then
    UI="plain"
    return 0
  fi

  case "$UI_PREF" in
    # Plain, coloured text prompts are the default: they render correctly on every
    # terminal, leave nothing painted behind, and never mangle typed input. A full
    # TUI (gum/whiptail/dialog) is opt-in via --tui or FORGEPANEL_UI=whiptail.
    plain|auto|"") UI="plain" ;;
    tui)
      if command -v gum >/dev/null 2>&1; then UI="gum"
      elif command -v whiptail >/dev/null 2>&1; then UI="whiptail"
      elif command -v dialog >/dev/null 2>&1; then UI="dialog"
      else UI="plain"; fi
      ;;
    gum|whiptail|dialog)
      if command -v "$UI_PREF" >/dev/null 2>&1; then UI="$UI_PREF"; else UI="plain"; fi
      ;;
    *) UI="plain" ;;
  esac
  # whiptail/dialog default to a backdrop that renders as a jarring magenta block
  # on some terminals (and can linger after the dialog closes). Pin a clean, dark
  # scheme so the backdrop matches a normal terminal instead.
  if [[ "$UI" == "whiptail" || "$UI" == "dialog" ]]; then
    export NEWT_COLORS='root=,black;window=white,black;shadow=,black;border=white,black;title=white,black;textbox=white,black;listbox=white,black;actlistbox=black,white;entry=white,black;button=black,white;actbutton=white,black;compactbutton=white,black;checkbox=white,black;actcheckbox=black,white'
  fi
}

# ---------------------------------------------------------------------------
# Prompt abstraction: ask / confirm / menu
# ---------------------------------------------------------------------------
_plain_ask() {
  local prompt="$1" def="${2:-}" ans=""
  if [[ -n "$def" ]]; then
    printf '   %s%s%s %s[%s]%s ' "$C_BOLD" "$prompt" "$C_RESET" "$C_DIM" "$def" "$C_RESET" >/dev/tty
  else
    printf '   %s%s%s ' "$C_BOLD" "$prompt" "$C_RESET" >/dev/tty
  fi
  IFS= read -r ans </dev/tty || ans=""
  if [[ -z "$ans" ]]; then ans="$def"; fi
  printf '%s' "$ans"
}

# ask <prompt> [default] -> prints the answer
ask() {
  local prompt="$1" def="${2:-}" out=""
  if [[ "$INTERACTIVE" != "1" ]]; then
    printf '%s' "$def"
    return 0
  fi
  # IMPORTANT: never seed the TUI input field with the default. whiptail/dialog
  # (and, less severely, gum) place the cursor at the END of a pre-filled value,
  # so a user typing "3000" over a default of "2053" gets "20533000" — a garbage
  # port/domain. Instead we start with an EMPTY field, show the default as a hint,
  # and fall back to it when the field is submitted blank.
  case "$UI" in
    gum)
      out=$(gum input --prompt "$ARROW $prompt " --placeholder "${def:-type a value}" \
              </dev/tty 2>/dev/tty || true)
      ;;
    whiptail|dialog)
      local label="$prompt"
      [[ -n "$def" ]] && label="$prompt"$'\n\n'"Leave blank to use the default: $def"
      out=$("$UI" --title "$TITLE" --inputbox "$label" 11 "$RULE_WIDTH" "" \
              3>&1 1>&2 2>&3 </dev/tty || true)
      ;;
    *)
      out=$(_plain_ask "$prompt" "$def")
      ;;
  esac
  if [[ -z "$out" ]]; then out="$def"; fi
  printf '%s' "$out"
}

# confirm <prompt> [yes|no] -> exit status 0 for yes
confirm() {
  local prompt="$1" def="${2:-yes}" ans=""
  if [[ "$INTERACTIVE" != "1" ]]; then
    [[ "$def" == "yes" ]] && return 0 || return 1
  fi
  case "$UI" in
    gum)
      if [[ "$def" == "yes" ]]; then
        gum confirm --default=true "$prompt" </dev/tty >/dev/tty 2>&1 && return 0 || return 1
      fi
      gum confirm --default=false "$prompt" </dev/tty >/dev/tty 2>&1 && return 0 || return 1
      ;;
    whiptail|dialog)
      if [[ "$def" == "yes" ]]; then
        "$UI" --title "$TITLE" --yesno "$prompt" 10 "$RULE_WIDTH" </dev/tty && return 0 || return 1
      fi
      "$UI" --title "$TITLE" --defaultno --yesno "$prompt" 10 "$RULE_WIDTH" </dev/tty && return 0 || return 1
      ;;
    *)
      local hint="[Y/n]"
      [[ "$def" == "yes" ]] || hint="[y/N]"
      while true; do
        printf '   %s%s%s %s%s%s ' "$C_BOLD" "$prompt" "$C_RESET" "$C_DIM" "$hint" "$C_RESET" >/dev/tty
        IFS= read -r ans </dev/tty || ans=""
        [[ -z "$ans" ]] && ans="$def"
        case "$ans" in
          [Yy]|[Yy][Ee][Ss]) return 0 ;;
          [Nn]|[Nn][Oo])     return 1 ;;
          *) printf '   %sPlease answer yes or no.%s\n' "$C_DIM" "$C_RESET" >/dev/tty ;;
        esac
      done
      ;;
  esac
}

# menu <prompt> <default> <option>... -> prints the chosen option
menu() {
  local prompt="$1" def="$2"; shift 2
  local options=("$@") out="" opt i
  if [[ "$INTERACTIVE" != "1" ]]; then
    printf '%s' "$def"
    return 0
  fi
  case "$UI" in
    gum)
      out=$(gum choose --header "$prompt" "${options[@]}" </dev/tty 2>/dev/tty || true)
      ;;
    whiptail|dialog)
      local pairs=()
      for opt in "${options[@]}"; do pairs+=("$opt" " "); done
      out=$("$UI" --title "$TITLE" --menu "$prompt" 16 "$RULE_WIDTH" "${#options[@]}" \
              "${pairs[@]}" 3>&1 1>&2 2>&3 </dev/tty || true)
      ;;
    *)
      printf '   %s%s%s\n' "$C_BOLD" "$prompt" "$C_RESET" >/dev/tty
      i=1
      for opt in "${options[@]}"; do
        printf '     %s%s)%s %s\n' "$C_CYAN" "$i" "$C_RESET" "$opt" >/dev/tty
        i=$((i + 1))
      done
      while true; do
        printf '   %sChoice%s %s[%s]%s ' "$C_BOLD" "$C_RESET" "$C_DIM" "$def" "$C_RESET" >/dev/tty
        IFS= read -r out </dev/tty || out=""
        if [[ -z "$out" ]]; then out="$def"; break; fi
        if [[ "$out" =~ ^[0-9]+$ ]] && (( out >= 1 && out <= ${#options[@]} )); then
          out="${options[$((out - 1))]}"
          break
        fi
        for opt in "${options[@]}"; do
          if [[ "$out" == "$opt" ]]; then break 2; fi
        done
        printf '   %sPick a number from the list.%s\n' "$C_DIM" "$C_RESET" >/dev/tty
      done
      ;;
  esac
  if [[ -z "$out" ]]; then out="$def"; fi
  printf '%s' "$out"
}

# ---------------------------------------------------------------------------
# Environment probes
# ---------------------------------------------------------------------------
require_root() {
  if [[ "$(id -u)" != "0" ]]; then
    err "This installer must run as root."
    printf '   Try:  %scurl -fsSL <install-url> | sudo bash%s\n\n' "$C_BOLD" "$C_RESET" >&2
    exit 1
  fi
}

require_tools() {
  if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    die "Neither curl nor wget is available. Install one of them and re-run."
  fi
  if ! command -v systemctl >/dev/null 2>&1; then
    die "systemd (systemctl) was not found. This installer targets systemd hosts."
  fi
  command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required to verify release assets."
  command -v file >/dev/null 2>&1 || die "file is required to validate release architecture."
}

detect_os() {
  if [[ -r /etc/os-release ]]; then
    local name="" version=""
    name=$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release | tr -d '"' | head -n1)
    if [[ -z "$name" ]]; then
      name=$(sed -n 's/^NAME=//p' /etc/os-release | tr -d '"' | head -n1)
      version=$(sed -n 's/^VERSION=//p' /etc/os-release | tr -d '"' | head -n1)
      name="${name} ${version}"
    fi
    OS_PRETTY=$(printf '%s' "$name" | sed 's/[[:space:]]*$//')
  fi
  [[ -n "$OS_PRETTY" ]] || OS_PRETTY="$(uname -s) $(uname -r)"
  OS_NAME="$(uname -s)"
  if [[ "$OS_NAME" != "Linux" ]]; then
    die "Unsupported operating system: ${OS_NAME}. ForgePanel releases are Linux-only."
  fi
}

detect_arch() {
  local machine
  machine="$(uname -m)"
  case "$machine" in
    x86_64|amd64)   ARCH="amd64" ;;
    aarch64|arm64)  ARCH="arm64" ;;
    *)
      err "Unsupported CPU architecture: ${machine}"
      printf '   Prebuilt releases exist for %sx86_64 (amd64)%s and %saarch64 (arm64)%s only.\n' \
        "$C_BOLD" "$C_RESET" "$C_BOLD" "$C_RESET" >&2
      printf '   You can still build from source: https://github.com/%s\n\n' "$REPO" >&2
      exit 1
      ;;
  esac
}

fetch_url() {
  # fetch_url <url> -> body on stdout (empty on failure)
  local url="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --max-time 12 "$url" 2>/dev/null || true
  else
    wget -qO- --timeout=12 "$url" 2>/dev/null || true
  fi
}

detect_public_ip() {
  # detect_public_ip <4|6> -> address on stdout
  local family="$1" url ip
  command -v curl >/dev/null 2>&1 || return 0
  for url in "https://api.ipify.org" "https://ifconfig.co" "https://icanhazip.com"; do
    ip=$(curl -"$family" -fsSL --max-time 6 "$url" 2>/dev/null | tr -d '[:space:]' || true)
    if [[ "$family" == "4" && "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
      printf '%s' "$ip"; return 0
    fi
    if [[ "$family" == "6" && "$ip" == *:* && "$ip" != *" "* ]]; then
      printf '%s' "$ip"; return 0
    fi
  done
  return 0
}

# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------
valid_port() {
  local p="$1"
  [[ "$p" =~ ^[0-9]+$ ]] || return 1
  (( p >= 1 && p <= 65535 )) || return 1
  return 0
}

port_in_use() {
  local p="$1" out=""
  if command -v ss >/dev/null 2>&1; then
    out=$(ss -ltn 2>/dev/null || true)
  elif command -v netstat >/dev/null 2>&1; then
    out=$(netstat -ltn 2>/dev/null || true)
  else
    return 1
  fi
  printf '%s\n' "$out" | awk '{print $4}' | grep -qE "[:.]${p}\$"
}

normalize_domain() {
  local d="$1"
  d="${d#http://}"
  d="${d#https://}"
  d="${d%%/*}"        # drop any path
  d="${d%%\?*}"       # drop any query string
  d="${d##*@}"        # drop user info
  d="${d#[}"; d="${d%]}"
  case "$d" in
    *:*[0-9]) d="${d%:*}" ;;
  esac
  d="${d%.}"
  printf '%s' "$(printf '%s' "$d" | tr '[:upper:]' '[:lower:]')"
}

valid_domain() {
  local d="$1"
  [[ ${#d} -le 253 ]] || return 1
  [[ "$d" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$ ]]
}

valid_email() {
  local e="$1"
  [[ "$e" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]]
}

resolve_host() {
  # resolve_host <hostname> -> one IP per line
  local host="$1" ips=""
  if command -v getent >/dev/null 2>&1; then
    ips=$(getent ahosts "$host" 2>/dev/null | awk '{print $1}' | sort -u || true)
  fi
  if [[ -z "$ips" ]] && command -v dig >/dev/null 2>&1; then
    ips=$( { dig +short A "$host" 2>/dev/null; dig +short AAAA "$host" 2>/dev/null; } \
             | grep -E '^[0-9a-fA-F:.]+$' | sort -u || true)
  fi
  if [[ -z "$ips" ]] && command -v host >/dev/null 2>&1; then
    ips=$(host "$host" 2>/dev/null | awk '/has (IPv6 )?address/ {print $NF}' | sort -u || true)
  fi
  printf '%s' "$ips" | grep -vE '^[[:space:]]*$' || true
}

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------
do_uninstall() {
  banner
  local args=(uninstall --data "$DATA_DIR" --manifest "$MANIFEST_PATH")
  [[ "$DO_PURGE" == "1" ]] && args+=(--purge)
  [[ "$DRY_RUN" == "1" ]] && args+=(--dry-run)
  [[ "$ASSUME_YES" == "1" ]] && args+=(--yes)
  if [[ -x "$CTL_PATH" ]]; then
    # forgectl stops the service and removes only ForgePanel-owned
    # forgepanel_porthop firewall state and manifest-proven files.
    if "$CTL_PATH" "${args[@]}"; then
      exit 0
    fi
    exit 1
  fi
  err "forgectl is required for a safe uninstall but is not installed."
  printf '   The legacy installer will not guess ownership or delete files without a manifest.\n' >&2
  exit 1
}

# ---------------------------------------------------------------------------
# Wizard steps
# ---------------------------------------------------------------------------
load_existing_config() {
  if [[ -f "$UNIT_PATH" || -x "$BIN_PATH" ]]; then
    UPGRADE=1
  fi
  if [[ -s "${DATA_DIR}/panel.json" ]]; then
    PANEL_CONFIG_EXISTS=1
    return 0
  fi
  # Legacy releases persisted mutable values in the unit environment. Read
  # those only once to migrate them into panel.json during this install.
  if [[ -r "$ENV_FILE" ]]; then
    PREV_PORT=$(sed -n 's/^FORGEPANEL_PANEL_PORT=//p' "$ENV_FILE" | head -n1)
    [[ -n "$PANEL_PORT"   ]] || PANEL_PORT="$PREV_PORT"
    [[ -n "$PANEL_DOMAIN" ]] || PANEL_DOMAIN=$(sed -n 's/^FORGEPANEL_DOMAIN=//p' "$ENV_FILE" | head -n1)
    [[ -n "$ACME_EMAIL"   ]] || ACME_EMAIL=$(sed -n 's/^FORGEPANEL_ACME_EMAIL=//p' "$ENV_FILE" | head -n1)
    [[ -n "$PANEL_HTTPS"  ]] || PANEL_HTTPS=$(sed -n 's/^FORGEPANEL_HTTPS=//p' "$ENV_FILE" | head -n1)
  fi
}

step_system() {
  step 1 "Inspecting this server"
  detect_os
  detect_arch
  ok "Operating system: ${OS_PRETTY}"
  ok "Architecture:     $(uname -m) ${C_DIM}(release: ${ARCH})${C_RESET}"
  if [[ "$UPGRADE" == "1" ]]; then
    info "An existing ForgePanel installation was found — this run will upgrade it."
  fi
  if [[ "$REPAIR" == "1" ]]; then
    info "Repair mode will verify and replace the managed binaries, unit, and manifest."
  fi
}

step_network() {
  step 2 "Detecting public addresses"
  IPV4=$(detect_public_ip 4)
  IPV6=$(detect_public_ip 6)
  if [[ -n "$IPV4" ]]; then
    ok "IPv4: ${IPV4}"
  else
    warn "Could not determine a public IPv4 address."
  fi
  if [[ -n "$IPV6" ]]; then
    ok "IPv6: ${IPV6}"
  else
    info "No public IPv6 address detected (that is fine)."
  fi
  SERVER_IP="${IPV4:-$IPV6}"
  if [[ -z "$SERVER_IP" ]]; then
    SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || true)
  fi
  [[ -n "$SERVER_IP" ]] || SERVER_IP="127.0.0.1"
}

step_version() {
  step 3 "Resolving the release to install"
  if [[ -n "$VERSION" ]]; then
    ok "Using pinned version: ${VERSION}"
    return 0
  fi
  info "Querying GitHub for the latest release..."
  local body
  body=$(fetch_url "https://api.github.com/repos/${REPO}/releases/latest")
  VERSION=$(printf '%s' "$body" | grep -oE '"tag_name"[[:space:]]*:[[:space:]]*"[^"]+"' | head -n1 | cut -d'"' -f4)
  if [[ -z "$VERSION" ]]; then
    err "No published release was found for ${REPO}."
    printf '   Check your network connection, or pin a version with %s--version <tag>%s.\n\n' \
      "$C_BOLD" "$C_RESET" >&2
    exit 1
  fi
  ok "Latest release: ${VERSION}"
}

step_port() {
  step 4 "Choosing the panel port"
  local candidate="${PANEL_PORT:-$DEFAULT_PORT}" attempts=0

  while true; do
    attempts=$((attempts + 1))
    candidate=$(ask "Panel port" "$candidate")

    if ! valid_port "$candidate"; then
      warn "\"${candidate}\" is not a valid port. Expected a number between 1 and 65535."
      if [[ "$INTERACTIVE" != "1" ]]; then
        info "Falling back to the default port ${DEFAULT_PORT}."
        candidate="$DEFAULT_PORT"
        break
      fi
      candidate="$DEFAULT_PORT"
      continue
    fi

    # An upgrade re-using its own port is not a conflict.
    if [[ "$UPGRADE" == "1" && -n "$PREV_PORT" && "$candidate" == "$PREV_PORT" ]]; then
      break
    fi

    if port_in_use "$candidate"; then
      warn "Port ${candidate} is already listening on this server."
      if [[ "$INTERACTIVE" != "1" ]]; then
        info "Continuing anyway — free the port or the service will fail to start."
        break
      fi
      if confirm "Pick a different port?" "yes"; then
        candidate=$((candidate + 1))
        valid_port "$candidate" || candidate="$DEFAULT_PORT"
        continue
      fi
      break
    fi
    break
  done

  PANEL_PORT="$candidate"
  ok "Panel will listen on port ${PANEL_PORT}."
  if (( attempts > 3 )); then
    info "Tip: pass --port <n> next time to skip this question."
  fi
}

step_domain() {
  step 5 "Domain and encryption"

  local want_domain="no"
  if [[ -n "$PANEL_DOMAIN" ]]; then
    want_domain="yes"
  elif confirm "Do you have a domain name pointed at this server?" "no"; then
    want_domain="yes"
  fi

  if [[ "$want_domain" != "yes" ]]; then
    PANEL_DOMAIN=""
    PANEL_HTTPS="0"
    info "No domain configured — the panel will be reachable over plain HTTP at"
    info "  http://${SERVER_IP}:${PANEL_PORT}"
    warn "Browser traffic to the panel will not be encrypted."
    info "Add a domain later from the panel settings to switch on automatic HTTPS."
    return 0
  fi

  local candidate="$PANEL_DOMAIN" ips choice matched
  while true; do
    candidate=$(ask "Panel domain (e.g. panel.example.com)" "$candidate")
    candidate=$(normalize_domain "$candidate")

    if [[ -z "$candidate" ]] || ! valid_domain "$candidate"; then
      warn "\"${candidate}\" does not look like a valid hostname."
      if [[ "$INTERACTIVE" != "1" ]]; then
        die "Invalid FORGEPANEL_DOMAIN. Fix it or drop it to install over plain HTTP."
      fi
      if confirm "Enter the domain again?" "yes"; then continue; fi
      PANEL_DOMAIN=""
      PANEL_HTTPS="0"
      info "Continuing without a domain."
      return 0
    fi

    info "Checking DNS for ${candidate}..."
    ips=$(resolve_host "$candidate")
    matched="no"
    if [[ -n "$ips" ]]; then
      while IFS= read -r one; do
        [[ -z "$one" ]] && continue
        if [[ -n "$IPV4" && "$one" == "$IPV4" ]] || [[ -n "$IPV6" && "$one" == "$IPV6" ]]; then
          matched="yes"
        fi
      done <<< "$ips"
    fi

    if [[ "$matched" == "yes" ]]; then
      ok "${candidate} resolves to this server."
      break
    fi

    if [[ -z "$ips" ]]; then
      warn "${candidate} does not resolve to any address yet."
    else
      warn "${candidate} resolves to: $(printf '%s' "$ips" | tr '\n' ' ')"
      warn "…which does not match this server (${SERVER_IP})."
    fi
    info "Certificate issuance needs the domain pointing here, with ports 80/443 reachable."

    if [[ "$INTERACTIVE" != "1" ]]; then
      info "Non-interactive mode: continuing with ${candidate} anyway."
      break
    fi

    choice=$(menu "How would you like to proceed?" "retry" \
      "retry - fix the DNS record and check again" \
      "proceed - use this domain anyway" \
      "skip - install without a domain" \
      "abort - stop the installer")
    case "$choice" in
      retry*)   continue ;;
      proceed*) break ;;
      skip*)
        PANEL_DOMAIN=""
        PANEL_HTTPS="0"
        info "Continuing without a domain."
        return 0
        ;;
      abort*)   die "Installation aborted at your request." ;;
      *)        continue ;;
    esac
  done

  PANEL_DOMAIN="$candidate"
  PANEL_HTTPS="1"

  # Contact address used when requesting certificates.
  local email="$ACME_EMAIL"
  while true; do
    email=$(ask "Contact e-mail for certificate notices (optional)" "$email")
    [[ -z "$email" ]] && break
    if valid_email "$email"; then break; fi
    warn "\"${email}\" does not look like an e-mail address."
    if [[ "$INTERACTIVE" != "1" ]]; then email=""; break; fi
    if ! confirm "Enter it again?" "yes"; then email=""; break; fi
  done
  ACME_EMAIL="$email"

  ok "Automatic HTTPS enabled for ${PANEL_DOMAIN}."
  if port_in_use 80; then
    warn "Port 80 is already in use — certificate issuance may fail until it is free."
  fi
}

apply_https_override() {
  if [[ "$HTTPS_FORCED" == "1" ]]; then PANEL_HTTPS="1"; fi
  if [[ "$HTTPS_FORCED" == "0" ]]; then PANEL_HTTPS="0"; fi
  [[ -n "$PANEL_HTTPS" ]] || PANEL_HTTPS="0"
  if [[ "$PANEL_HTTPS" == "1" && -z "$PANEL_DOMAIN" ]]; then
    warn "Automatic HTTPS needs a domain; falling back to plain HTTP."
    PANEL_HTTPS="0"
  fi
}

panel_scheme() {
  if [[ "$PANEL_HTTPS" == "1" ]]; then printf 'https'; else printf 'http'; fi
}

panel_base_url() {
  local host="${PANEL_DOMAIN:-$SERVER_IP}"
  if [[ "$host" == *:* && "$host" != *"["* ]]; then host="[${host}]"; fi
  printf '%s://%s:%s' "$(panel_scheme)" "$host" "$PANEL_PORT"
}

step_summary() {
  step 6 "Review"
  rule
  kv "Release"      "$VERSION"
  kv "Architecture" "linux/${ARCH}"
  kv "Binary"       "$BIN_PATH"
  kv "Data dir"     "$DATA_DIR"
  kv "Service"      "${SERVICE}.service"
  kv "Port"         "$PANEL_PORT"
  if [[ -n "$PANEL_DOMAIN" ]]; then
    kv "Domain"     "$PANEL_DOMAIN"
  else
    kv "Domain"     "${C_DIM}(none — using ${SERVER_IP})${C_RESET}"
  fi
  if [[ "$PANEL_HTTPS" == "1" ]]; then
    kv "Encryption"  "${C_GREEN}automatic HTTPS${C_RESET}"
    kv "Contact"     "${ACME_EMAIL:-${C_DIM}(not set)${C_RESET}}"
  else
    kv "Encryption"  "${C_YELLOW}plain HTTP${C_RESET}"
  fi
  kv "Panel URL"    "$(panel_base_url)/…"
  rule
  printf '\n'
  if ! confirm "Install ForgePanel with these settings?" "yes"; then
    die "Cancelled — nothing was installed."
  fi
}

# ---------------------------------------------------------------------------
# Installation
# ---------------------------------------------------------------------------
download_to() {
  # download_to <url> <dest>; returns non-zero on failure
  local url="$1" dest="$2"
  if command -v curl >/dev/null 2>&1; then
    if [[ "$INTERACTIVE" == "1" && "$UI" == "plain" ]]; then
      curl -fL --retry 3 --retry-delay 2 --connect-timeout 15 --progress-bar -o "$dest" "$url"
    else
      curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 15 -o "$dest" "$url"
    fi
  else
    wget -q --tries=3 --timeout=30 -O "$dest" "$url"
  fi
}

write_unit() {
  mkdir -p "$ENV_DIR"
  local env_tmp="${ENV_FILE}.tmp"
  {
    printf '# Generated by the ForgePanel installer on %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf '# Mutable panel address, domain, HTTPS and ACME settings live in panel.json.\n'
    printf '# This file intentionally contains only immutable bootstrap state.\n'
    printf 'FORGEPANEL_DATA=%s\n' "$DATA_DIR"
  } > "$env_tmp"
  chmod 0600 "$env_tmp"
  mv -f "$env_tmp" "$ENV_FILE"

  # Kept deliberately in step with packaging/systemd/forgepanel.service so that a
  # curl-install and a deb/rpm install produce the same runtime behaviour.
  #
  # StateDirectory= is always relative to /var/lib, so it only applies when the
  # data directory is left at its default; a custom --data dir is created by the
  # installer instead and merely whitelisted for writing.
  local state_line=""
  if [[ "$DATA_DIR" == "$DEFAULT_DATA" ]]; then
    state_line=$'StateDirectory=forgepanel\nStateDirectoryMode=0700'
  fi
  # ProtectHome= would hide a data directory placed under /home.
  local protect_home="ProtectHome=true"
  case "$DATA_DIR" in
    /home/*|/root/*) protect_home="ProtectHome=false" ;;
  esac

  local unit_tmp="${UNIT_PATH}.tmp"
  cat > "$unit_tmp" <<UNIT
# Generated by the ForgePanel installer. Re-running the installer overwrites
# this file; mutable settings belong in panel.json via the UI or forgectl.
[Unit]
Description=ForgePanel — proxy management panel
Documentation=https://github.com/${REPO}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN_PATH}
WorkingDirectory=${DATA_DIR}
Environment=FORGEPANEL_DATA=${DATA_DIR}
EnvironmentFile=-${ENV_FILE}
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
${state_line}

# Needed to bind 80/443 for certificate issuance and HTTPS, 53/udp for DNS, and
# to program the firewall rules used by port-hopping transports.
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN

# Hardening — deliberately stops short of settings that would break engine
# process management or writing generated engine configs under ${ENV_DIR}.
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
${protect_home}
ProtectKernelTunables=true
# ProtectKernelModules disabled to allow AmneziaWG/WireGuard kernel modules
ProtectKernelModules=false
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictNamespaces=false
LockPersonality=true
# /etc/ufw writable (optional via '-') so the panel can open the host firewall for
# inbound ports at runtime; ufw persists rules there and ProtectSystem=full would
# otherwise make it read-only, silently breaking auto-firewalling.
ReadWritePaths=${DATA_DIR} ${ENV_DIR} -/etc/ufw

[Install]
WantedBy=multi-user.target
UNIT
  chmod 0644 "$unit_tmp"
  mv -f "$unit_tmp" "$UNIT_PATH"
}

# open_firewall opens the ports the panel itself binds — the panel UI/API port,
# 80 and 443 (ACME HTTP-01 + HTTPS/TLS-ALPN + QUIC), and 53 (ForgeDNS) — on
# whatever managed host firewall is active. Proxy inbound ports are opened by the
# panel at runtime (internal/firewall). Best-effort and idempotent: it never
# installs a firewall, and on a host with no managed firewall it just advises.
open_firewall() {
  local tcp=(80 443 53 "$PANEL_PORT") udp=(53 443)
  # de-duplicate (PANEL_PORT may already be 80/443/53)
  local seen=" " p list_tcp=()
  for p in "${tcp[@]}"; do case "$seen" in *" $p "*) ;; *) list_tcp+=("$p"); seen="$seen$p ";; esac; done

  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    for p in "${list_tcp[@]}"; do ufw allow "${p}/tcp" >/dev/null 2>&1 || true; done
    for p in "${udp[@]}"; do ufw allow "${p}/udp" >/dev/null 2>&1 || true; done
    ufw reload >/dev/null 2>&1 || true
    ok "Firewall (ufw): opened tcp ${list_tcp[*]} and udp ${udp[*]}."
    return 0
  fi
  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    for p in "${list_tcp[@]}"; do firewall-cmd --permanent --add-port="${p}/tcp" >/dev/null 2>&1 || true; done
    for p in "${udp[@]}"; do firewall-cmd --permanent --add-port="${p}/udp" >/dev/null 2>&1 || true; done
    firewall-cmd --reload >/dev/null 2>&1 || true
    ok "Firewall (firewalld): opened tcp ${list_tcp[*]} and udp ${udp[*]}."
    return 0
  fi
  # Raw iptables — only touch it when there is actually a restrictive INPUT policy
  # to open (DROP/REJECT). If INPUT already defaults to ACCEPT, adding rules would
  # be noise, and we must not risk disturbing a hand-built ruleset.
  if command -v iptables >/dev/null 2>&1 && iptables -L INPUT -n 2>/dev/null | head -1 | grep -qiE 'policy (DROP|REJECT)'; then
    for p in "${list_tcp[@]}"; do iptables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || true; done
    for p in "${udp[@]}"; do iptables -C INPUT -p udp --dport "$p" -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport "$p" -j ACCEPT 2>/dev/null || true; done
    command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true
    ok "Firewall (iptables): allowed tcp ${list_tcp[*]} and udp ${udp[*]}."
    return 0
  fi
  info "No active host firewall detected. If your VPS provider has an external firewall,"
  info "allow: TCP ${list_tcp[*]} and UDP ${udp[*]} (80/443 are needed for automatic TLS)."
  return 0
}

step_install() {
  step 7 "Installing"

  local base="https://github.com/${REPO}/releases/download/${VERSION}"
  local tmp data_created=0 was_active=0
  tmp=$(mktemp -d /tmp/forgepanel-install.XXXXXX)
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT

  for asset in "forgepanel-linux-${ARCH}" "forgectl-linux-${ARCH}" "forgenode-linux-${ARCH}"; do
    info "Downloading ${asset} (${VERSION})..."
    download_to "${base}/${asset}" "${tmp}/${asset}" || die "Download failed: ${base}/${asset}"
  done
  download_to "${base}/checksums.txt" "${tmp}/checksums.txt" || die "Release checksums are unavailable; aborting before changing this host."
  for asset in "forgepanel-linux-${ARCH}" "forgectl-linux-${ARCH}" "forgenode-linux-${ARCH}"; do
    verify_release_asset "${tmp}/${asset}" "$asset" "${tmp}/checksums.txt" || die "Checksum verification failed for ${asset}."
    validate_binary "${tmp}/${asset}" || die "${asset} is not a valid linux/${ARCH} executable."
  done
  ok "Release assets verified."

  if [[ "$DRY_RUN" == "1" ]]; then
    info "Dry run: verified release assets would replace ${BIN_PATH}, ${CTL_PATH}, ${NODE_PATH}, ${UNIT_PATH}, and ${ENV_FILE}."
    info "Dry run: no service, firewall, file, or configuration change was made."
    return 0
  fi

  if [[ -d "$DATA_DIR" ]]; then
    data_created=0
  else
    data_created=1
    mkdir -p "$DATA_DIR"
  fi
  chmod 0700 "$DATA_DIR"
  local backup_dir
  backup_dir="${DATA_DIR}/install-backups/$(date -u '+%Y%m%dT%H%M%SZ')"
  mkdir -p "$backup_dir"
  chmod 0700 "$backup_dir"
  local bin_backup ctl_backup node_backup unit_backup env_backup
  bin_backup=$(backup_existing "$BIN_PATH" "${backup_dir}/forgepanel")
  ctl_backup=$(backup_existing "$CTL_PATH" "${backup_dir}/forgectl")
  node_backup=$(backup_existing "$NODE_PATH" "${backup_dir}/forgenode")
  unit_backup=$(backup_existing "$UNIT_PATH" "${backup_dir}/forgepanel.service")
  env_backup=$(backup_existing "$ENV_FILE" "${backup_dir}/forgepanel.env")
  if systemctl is-active --quiet "$SERVICE" 2>/dev/null; then was_active=1; fi

  rollback_install() {
    err "Installation did not pass validation; restoring the previous state."
    systemctl stop "$SERVICE" >/dev/null 2>&1 || true
    restore_or_remove "$BIN_PATH" "$bin_backup"
    restore_or_remove "$CTL_PATH" "$ctl_backup"
    restore_or_remove "$NODE_PATH" "$node_backup"
    restore_or_remove "$UNIT_PATH" "$unit_backup"
    restore_or_remove "$ENV_FILE" "$env_backup"
    systemctl daemon-reload >/dev/null 2>&1 || true
    if [[ "$was_active" == "1" ]]; then systemctl start "$SERVICE" >/dev/null 2>&1 || true; fi
    if [[ "$data_created" == "1" ]]; then rm -rf "${DATA_DIR:?}"; fi
    exit 1
  }

  if [[ "$was_active" == "1" ]]; then
    info "Stopping the running service before replacing the binaries..."
    systemctl stop "$SERVICE" || rollback_install
  fi
  install_atomic "${tmp}/forgepanel-linux-${ARCH}" "$BIN_PATH" || rollback_install
  install_atomic "${tmp}/forgectl-linux-${ARCH}" "$CTL_PATH" || rollback_install
  install_atomic "${tmp}/forgenode-linux-${ARCH}" "$NODE_PATH" || rollback_install
  write_unit || rollback_install
  systemctl daemon-reload || rollback_install

  # One-time migration of installer input into panel.json. The unit environment
  # afterwards contains only FORGEPANEL_DATA, so web and terminal settings stay
  # authoritative across reboots and upgrades.
  local settings_args=(settings set --defer-restart --data "$DATA_DIR")
  if [[ "$PANEL_CONFIG_EXISTS" == "0" ]]; then
    settings_args+=(--bootstrap --panel-port "$PANEL_PORT" --domain "$PANEL_DOMAIN" --https "$PANEL_HTTPS" --acme-email "$ACME_EMAIL")
  else
    # Do not let an upgrade's wizard defaults overwrite persisted panel.json.
    # Explicit command-line/environment input remains an intentional change.
    [[ "$PORT_EXPLICIT" == "1" ]] && settings_args+=(--panel-port "$PANEL_PORT")
    [[ "$DOMAIN_EXPLICIT" == "1" ]] && settings_args+=(--domain "$PANEL_DOMAIN")
    [[ "$HTTPS_EXPLICIT" == "1" ]] && settings_args+=(--https "$PANEL_HTTPS")
    [[ "$EMAIL_EXPLICIT" == "1" ]] && settings_args+=(--acme-email "$ACME_EMAIL")
  fi
  if (( ${#settings_args[@]} > 5 )); then
    "$CTL_PATH" "${settings_args[@]}" || rollback_install
  fi

  "$BIN_PATH" --version | grep -Fq " ${VERSION} " || rollback_install
  "$CTL_PATH" version | grep -Fq " ${VERSION} " || rollback_install
  systemctl enable "$SERVICE" || rollback_install
  systemctl restart "$SERVICE" || rollback_install
  # A first boot opens the SQLite DB, runs migrations, initialises the engines and
  # (with a domain) starts ACME before it binds the panel port, so a single probe
  # right after restart can race the listener and see "connection refused". Poll
  # for up to ~40s and only roll back if it never comes up — but if the service
  # itself has already failed, stop early and surface why.
  local hc_ok=0 hc_i
  for hc_i in $(seq 1 40); do
    if "$CTL_PATH" healthcheck "$PANEL_PORT" >/dev/null 2>&1; then hc_ok=1; break; fi
    if ! systemctl is-active --quiet "$SERVICE"; then
      err "The ${SERVICE} service failed to start. Recent log:"
      journalctl -u "$SERVICE" -n 20 --no-pager 2>/dev/null | sed 's/^/    /' >&2 || true
      rollback_install
    fi
    sleep 1
  done
  [[ "$hc_ok" == "1" ]] || { err "Panel did not answer its health check within 40s. Recent log:"; journalctl -u "$SERVICE" -n 20 --no-pager 2>/dev/null | sed 's/^/    /' >&2 || true; rollback_install; }

  local data_marker=""
  [[ "$data_created" == "1" ]] && data_marker=x
  local resources=(
    --resource "binary:${BIN_PATH}:$(created_flag "$bin_backup")"
    --resource "cli:${CTL_PATH}:$(created_flag "$ctl_backup")"
    --resource "node:${NODE_PATH}:$(created_flag "$node_backup")"
    --resource "unit:${UNIT_PATH}:$(created_flag "$unit_backup")"
    --resource "env:${ENV_FILE}:$(created_flag "$env_backup")"
    --resource "data_dir:${DATA_DIR}:$(created_flag "$data_marker")"
  )
  [[ -n "$bin_backup" ]] && resources+=(--backup "${BIN_PATH}=${bin_backup}")
  [[ -n "$ctl_backup" ]] && resources+=(--backup "${CTL_PATH}=${ctl_backup}")
  [[ -n "$node_backup" ]] && resources+=(--backup "${NODE_PATH}=${node_backup}")
  [[ -n "$unit_backup" ]] && resources+=(--backup "${UNIT_PATH}=${unit_backup}")
  [[ -n "$env_backup" ]] && resources+=(--backup "${ENV_FILE}=${env_backup}")
  "$CTL_PATH" lifecycle record-install --method curl --version "$VERSION" --data "$DATA_DIR" --manifest "$MANIFEST_PATH" "${resources[@]}" || rollback_install
  ok "Service started and health check passed."

  # Open the ports the panel binds so the panel, automatic TLS and ForgeDNS are
  # reachable without a manual firewall step. Best-effort — never fatal.
  open_firewall || true
}

verify_release_asset() {
  local file="$1" asset="$2" checksums="$3" expected
  expected=$(awk -v name="$asset" '$2 == name || $2 == ("*" name) { print $1; exit }' "$checksums")
  [[ "$expected" =~ ^[a-fA-F0-9]{64}$ ]] || return 1
  printf '%s  %s\n' "$expected" "$file" | sha256sum -c - >/dev/null
}

validate_binary() {
  local file="$1" desc
  [[ -s "$file" ]] || return 1
  desc=$(file -Lb "$file" 2>/dev/null) || return 1
  [[ "$desc" == *ELF* && "$desc" == *executable* ]] || return 1
  case "$ARCH" in
    amd64) [[ "$desc" == *x86-64* ]] ;;
    arm64) [[ "$desc" == *aarch64* || "$desc" == *ARM\ aarch64* ]] ;;
    *) return 1 ;;
  esac
}

backup_existing() {
  local target="$1" backup="$2"
  if [[ -e "$target" || -L "$target" ]]; then
    cp -a "$target" "$backup"
    printf '%s' "$backup"
  fi
}

created_flag() {
  [[ -z "$1" ]] && printf 'true' || printf 'false'
}

restore_or_remove() {
  local target="$1" backup="$2"
  if [[ -n "$backup" && -e "$backup" ]]; then
    cp -a "$backup" "$target"
  else
    rm -f "$target"
  fi
}

install_atomic() {
  local source="$1" target="$2" temp="${2}.new"
  install -m 0755 "$source" "$temp"
  mv -f "$temp" "$target"
}

wait_for_first_boot() {
  local token_file="${DATA_DIR}/setup-token.txt"
  local url_file="${DATA_DIR}/panel-url.txt"
  local i=0
  info "Waiting for first-boot files (setup token and panel URL)..."
  while (( i < 15 )); do
    if [[ -s "$token_file" && -s "$url_file" ]]; then
      return 0
    fi
    if ! systemctl is-active --quiet "$SERVICE" 2>/dev/null; then
      break
    fi
    sleep 1
    i=$((i + 1))
  done
  [[ -s "$token_file" && -s "$url_file" ]]
}

read_trim() {
  local f="$1"
  [[ -s "$f" ]] || return 1
  head -n1 "$f" | tr -d '\r' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//'
}

# ---------------------------------------------------------------------------
# Completion screen
# ---------------------------------------------------------------------------
show_completion() {
  local state panel_url setup_token first_boot_ok="$1"

  state=$(systemctl is-active "$SERVICE" 2>/dev/null || true)
  [[ -n "$state" ]] || state="unknown"
  panel_url=$(read_trim "${DATA_DIR}/panel-url.txt" || true)
  setup_token=$(read_trim "${DATA_DIR}/setup-token.txt" || true)
  [[ -n "$panel_url" ]] || panel_url="$(panel_base_url)/panel/<generated-path>"

  printf '\n'
  rule "$C_GREEN"
  printf ' %s%s ForgePanel %s is installed.%s\n' "$C_BOLD$C_GREEN" "$TICK" "$VERSION" "$C_RESET"
  rule "$C_GREEN"
  printf '\n'

  if [[ "$state" == "active" ]]; then
    kv "Service" "${C_GREEN}${state}${C_RESET} (${SERVICE}.service)"
  else
    kv "Service" "${C_RED}${state}${C_RESET} (${SERVICE}.service)"
  fi
  kv "Server IP" "${IPV4:-n/a}${IPV6:+  /  ${IPV6}}"
  if [[ -n "$PANEL_DOMAIN" ]]; then
    kv "Domain" "$PANEL_DOMAIN"
  else
    kv "Domain" "${C_DIM}not configured${C_RESET}"
  fi
  kv "Port" "$PANEL_PORT"
  if [[ "$PANEL_HTTPS" == "1" ]]; then
    kv "Encryption" "${C_GREEN}HTTPS (certificates issued automatically)${C_RESET}"
  else
    kv "Encryption" "${C_YELLOW}HTTP only — add a domain to enable HTTPS${C_RESET}"
  fi
  kv "Data dir" "$DATA_DIR"

  printf '\n'
  rule "$C_CYAN"
  printf ' %sFirst run — create your administrator account%s\n' "$C_BOLD$C_CYAN" "$C_RESET"
  rule "$C_CYAN"
  printf '\n'
  printf '   %s1.%s Open the panel:\n' "$C_BOLD" "$C_RESET"
  printf '        %s%s%s\n\n' "$C_BOLD$C_CYAN" "$panel_url" "$C_RESET"
  if [[ -n "$setup_token" ]]; then
    printf '   %s2.%s Enter this one-time setup token when asked:\n' "$C_BOLD" "$C_RESET"
    printf '        %s%s%s\n\n' "$C_BOLD$C_MAGENTA" "$setup_token" "$C_RESET"
  else
    printf '   %s2.%s Read the one-time setup token from the server:\n' "$C_BOLD" "$C_RESET"
    printf '        %scat %s/setup-token.txt%s\n\n' "$C_BOLD" "$DATA_DIR" "$C_RESET"
  fi
  printf '   %s3.%s Choose your admin username and password on the setup page.\n' "$C_BOLD" "$C_RESET"
  printf '      %sThe token works once and is invalidated as soon as the account exists.%s\n' \
    "$C_DIM" "$C_RESET"
  printf '      %sKeep the panel URL private — it contains a secret path.%s\n' "$C_DIM" "$C_RESET"

  if [[ "$first_boot_ok" != "0" ]]; then
    printf '\n'
    warn "The first-boot files did not appear within 15 seconds."
    printf '   Check the log with: %sjournalctl -u %s -e%s\n' "$C_BOLD" "$SERVICE" "$C_RESET"
  fi

  printf '\n'
  rule
  printf ' %sManaging the service%s\n' "$C_BOLD" "$C_RESET"
  rule
  kv "status"     "systemctl status ${SERVICE}"
  kv "restart"    "systemctl restart ${SERVICE}"
  kv "stop"       "systemctl stop ${SERVICE}"
  kv "live logs"  "journalctl -u ${SERVICE} -f"
  kv "settings"   "${ENV_FILE}"
  kv "upgrade"    "re-run this installer"
  kv "uninstall"  "bash install.sh --uninstall"
  printf '\n'
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
main() {
  parse_args "$@"
  require_root
  detect_ui

  if [[ "$DO_UNINSTALL" == "1" ]]; then
    do_uninstall
  fi
  if [[ "$DO_PURGE" == "1" ]]; then
    die "--purge is valid only together with --uninstall."
  fi

  require_tools
  load_existing_config

  banner
  if [[ "$INTERACTIVE" != "1" ]]; then
    info "Running non-interactively — using defaults and supplied settings."
  fi

  step_system
  step_network
  step_version
  step_port
  step_domain
  apply_https_override
  step_summary
  step_install

  if [[ "$DRY_RUN" == "1" ]]; then
    printf '\nDry run complete — no system state was changed.\n\n'
    exit 0
  fi

  local first_boot_ok=0
  wait_for_first_boot || first_boot_ok=1
  show_completion "$first_boot_ok"
}

main "$@"
