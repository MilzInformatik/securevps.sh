#!/usr/bin/env bash
#
# securevps.sh - harden a Debian or Ubuntu VPS.
#
# Every hardening step is a command that runs on its own, takes flags, is
# idempotent, and can be undone.
#
#   securevps.sh harden                 run every step in the profile
#   securevps.sh ssh --port 2222        one step, tuned
#   securevps.sh scan                   read-only report
#   securevps.sh revert ssh             undo it
#
# The file reads top to bottom in three parts: the helpers every command is
# built from, the settings table, then the commands themselves. Each command
# carries a description of what it changes and why above it.
#
# https://github.com/MilzInformatik/securevps.sh

set -euo pipefail


# --------------------------------------------------------------------------
# 1. constants and globals
# --------------------------------------------------------------------------

readonly SV_VERSION="0.1.0"
readonly SV_BACKUP_ROOT="/var/backups/securevps"
readonly SV_STATE_DIR="/var/lib/securevps"

# Modules in the order harden runs them. Order matters: the firewall opens the
# new SSH port before the ssh module moves sshd onto it, and docker comes after
# the firewall so its chain rules survive a ufw reload.
readonly SV_MODULE_ORDER=(
  updates user firewall ssh docker bruteforce sysctl kmodules
  pam services time logging apparmor banner mounts integrity
  mfa vpn alerts backup
)

# core is the default: the six steps that matter on any internet-facing VPS
# and whose effects are easy to explain and easy to undo. standard adds the
# rest, minimal is core without the two steps that touch accounts and Docker.
readonly SV_PROFILE_CORE=(updates user firewall ssh docker bruteforce)
readonly SV_PROFILE_MINIMAL=(updates ssh firewall bruteforce sysctl time banner)
readonly SV_PROFILE_STANDARD=(
  updates user firewall ssh docker bruteforce sysctl kmodules
  pam services time logging apparmor banner mounts
)

# Runtime state.
SV_CMD=""                 # harden | scan | revert | confirm | <module> | help
SV_CMD_GIVEN=0            # whether the command was typed or defaulted
SV_ACTIVE_MODULE=""       # set when a single module runs, enables short flags
SV_RUN_ID=""
SV_BACKUP_DIR=""
SV_MANIFEST=""
SV_CHANGED=0              # set by sv_write_file and friends on every call
SV_MODULE_CHANGES=0       # per-module change counter
SV_REBOOT_REQUIRED=0
declare -a SV_RUN_MODULES=()
declare -a SV_REVERT_TARGETS=()
declare -a SV_NOTES=()

# Scan tallies.
SV_SCAN_PASS=0
SV_SCAN_FAIL=0
SV_SCAN_WARN=0
SV_SCAN_SKIP=0
declare -a SV_SCAN_JSON=()

# Detected system facts, filled by sv_detect_system.
SV_OS_ID=""
SV_OS_VERSION=""
SV_OS_PRETTY=""
SV_HAS_SYSTEMD=0
SV_HAS_DOCKER=0
SV_IS_CONTAINER=0
SV_CLIENT_IP=""
SV_CURRENT_SSH_PORTS=""

# One line per module for the help output.
declare -A MODULE_DESC=(
  [updates]="security patches, applied now and automatically"
  [user]="a non-root administrator, and root locked down behind it"
  [firewall]="default-deny inbound with only the ports you asked for"
  [ssh]="key-only sshd with modern crypto and a rollback timer"
  [docker]="stop published container ports bypassing the firewall"
  [bruteforce]="ban addresses that keep failing to log in"
  [sysctl]="kernel and network stack hardening"
  [kmodules]="blacklist filesystems and protocols a VPS never uses"
  [pam]="password quality, lockout after repeated failures, ageing"
  [services]="stop and disable services a VPS rarely needs"
  [time]="a correct clock, which TLS and log correlation depend on"
  [logging]="logs that survive a reboot and an audit trail"
  [apparmor]="AppArmor profiles in enforce rather than complain mode"
  [banner]="a legal warning banner, and no OS version before login"
  [mounts]="nodev, nosuid and noexec on the writable scratch directories"
  [integrity]="AIDE, so you can tell what changed on disk (off by default)"
  [mfa]="a TOTP code on top of the SSH key (off by default)"
  [vpn]="WireGuard or Tailscale, so SSH need not face the internet"
  [alerts]="tell someone when a person logs in (off by default)"
  [backup]="restic and a timer, pointed at a repository you supply"
)


# --------------------------------------------------------------------------
# 2. helpers: output
# --------------------------------------------------------------------------

if [[ -t 1 && "${NO_COLOR:-}" == "" && "${TERM:-dumb}" != "dumb" ]]; then
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
  C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'; C_CYAN=$'\033[36m'
else
  C_RESET=""; C_BOLD=""; C_DIM=""
  C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_CYAN=""
fi

sv_quiet() { [[ "$(sv_get core.quiet)" == "true" ]]; }
sv_is_verbose() { [[ "$(sv_get core.verbose)" == "true" ]]; }
sv_is_json() { [[ "$(sv_get core.json)" == "true" ]]; }

sv_say()  { sv_quiet || sv_is_json || printf '%s\n' "$*"; }
sv_info() { sv_quiet || sv_is_json || printf '%s\n' "${C_BLUE}..${C_RESET} $*"; }
sv_ok()   { sv_quiet || sv_is_json || printf '%s\n' "${C_GREEN}ok${C_RESET} $*"; }
sv_skip() { sv_quiet || sv_is_json || printf '%s\n' "${C_DIM}--${C_RESET} ${C_DIM}$*${C_RESET}"; }
sv_warn() { sv_is_json || printf '%s\n' "${C_YELLOW}!!${C_RESET} $*" >&2; }
sv_err()  { printf '%s\n' "${C_RED}xx${C_RESET} $*" >&2; }
sv_debug() {
  sv_is_verbose || return 0
  sv_is_json && return 0
  printf '%s\n' "${C_DIM}   $*${C_RESET}" >&2
}

sv_die() { sv_err "$*"; exit 1; }

sv_header() {
  sv_quiet || sv_is_json || printf '\n%s\n' "${C_BOLD}${C_CYAN}== $*${C_RESET}"
}

# Queued for the end of the run so important warnings are not lost in scroll.
sv_note() { SV_NOTES+=("$*"); }

sv_dry() { [[ "$(sv_get core.dry-run)" == "true" ]]; }

# Would-do line, used in place of an action under --dry-run.
sv_would() { sv_quiet || sv_is_json || printf '%s\n' "${C_YELLOW}dry${C_RESET} $*"; }

# Ask a yes/no question. Returns 0 for yes. --yes answers yes, non-interactive
# answers with the default.
sv_confirm() {
  local prompt="$1" default="${2:-n}" reply
  if [[ "$(sv_get core.yes)" == "true" ]]; then return 0; fi
  if [[ ! -t 0 ]]; then [[ "$default" == "y" ]]; return; fi
  local hint="[y/N]"; [[ "$default" == "y" ]] && hint="[Y/n]"
  read -r -p "$prompt $hint " reply || reply=""
  reply="${reply:-$default}"
  [[ "${reply,,}" == "y" || "${reply,,}" == "yes" ]]
}


# --------------------------------------------------------------------------
# 3. helpers: system detection
# --------------------------------------------------------------------------

sv_detect_system() {
  [[ -r /etc/os-release ]] || sv_die "no /etc/os-release, this is not a distribution I know"
  # shellcheck disable=SC1091
  . /etc/os-release
  SV_OS_ID="${ID:-unknown}"
  SV_OS_VERSION="${VERSION_ID:-}"
  SV_OS_PRETTY="${PRETTY_NAME:-$SV_OS_ID $SV_OS_VERSION}"

  local like="${ID_LIKE:-}"
  if [[ "$SV_OS_ID" != debian && "$SV_OS_ID" != ubuntu && "$like" != *debian* ]]; then
    sv_err "securevps.sh $SV_VERSION supports Debian and Ubuntu."
    sv_err "This machine reports: $SV_OS_PRETTY"
    sv_die "Refusing to touch a system whose conventions I cannot verify."
  fi

  [[ -d /run/systemd/system ]] && SV_HAS_SYSTEMD=1
  command -v docker >/dev/null 2>&1 && SV_HAS_DOCKER=1

  if [[ -f /.dockerenv ]] || grep -qa 'container=' /proc/1/environ 2>/dev/null; then
    SV_IS_CONTAINER=1
  fi

  # The address this session came from, so fail2ban and the firewall can
  # avoid locking out the person doing the hardening.
  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    SV_CLIENT_IP="${SSH_CONNECTION%% *}"
  elif [[ -n "${SSH_CLIENT:-}" ]]; then
    SV_CLIENT_IP="${SSH_CLIENT%% *}"
  fi

  SV_CURRENT_SSH_PORTS="$(sv_current_sshd_ports)"
  sv_debug "os=$SV_OS_ID $SV_OS_VERSION systemd=$SV_HAS_SYSTEMD docker=$SV_HAS_DOCKER container=$SV_IS_CONTAINER client=${SV_CLIENT_IP:-none} sshd_ports=${SV_CURRENT_SSH_PORTS:-none}"
}

# Ports sshd is configured to listen on right now, space separated.
sv_current_sshd_ports() {
  local ports=""
  if command -v sshd >/dev/null 2>&1; then
    ports="$(sshd -T 2>/dev/null | awk '$1=="port"{print $2}' | tr '\n' ' ' || true)"
  fi
  if [[ -z "${ports// /}" && -r /etc/ssh/sshd_config ]]; then
    ports="$(grep -rhiE '^[[:space:]]*Port[[:space:]]+[0-9]+' \
      /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null \
      | awk '{print $2}' | tr '\n' ' ' || true)"
  fi
  [[ -z "${ports// /}" ]] && ports="22"
  # Empty fields sort ahead of the numbers and leave a leading space behind,
  # which then reads as a port change that never happened.
  printf '%s' "$(printf '%s\n' "$ports" | tr ' ' '\n' | grep -E '^[0-9]+$' \
    | sort -un | tr '\n' ' ' | sed 's/ $//')"
}

sv_require_root() {
  [[ "$(id -u)" -eq 0 ]] || sv_die "securevps.sh must run as root. Try: sudo $0 $SV_CMD"
}

sv_has_cmd() { command -v "$1" >/dev/null 2>&1; }


# --------------------------------------------------------------------------
# 4. helpers: packages and services
# --------------------------------------------------------------------------

SV_APT_UPDATED=0

sv_apt_update() {
  [[ $SV_APT_UPDATED -eq 1 ]] && return 0
  if sv_dry; then sv_would "apt-get update"; SV_APT_UPDATED=1; return 0; fi
  sv_debug "apt-get update"
  DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 \
    || sv_warn "apt-get update failed, package installs may use a stale index"
  SV_APT_UPDATED=1
}

sv_pkg_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q '^install ok installed$'; }

# Install packages, skipping any already present. Returns non-zero if any
# package could not be installed, without aborting the run.
sv_pkg_install() {
  local -a missing=()
  local p
  for p in "$@"; do sv_pkg_installed "$p" || missing+=("$p"); done
  [[ ${#missing[@]} -eq 0 ]] && return 0
  if sv_dry; then sv_would "apt-get install ${missing[*]}"; return 0; fi
  sv_apt_update
  sv_info "installing ${missing[*]}"
  if ! DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
       -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
       "${missing[@]}" >/dev/null 2>&1; then
    sv_warn "could not install: ${missing[*]}"
    return 1
  fi
  SV_MODULE_CHANGES=$((SV_MODULE_CHANGES + 1))
  return 0
}

sv_pkg_purge() {
  local -a present=()
  local p
  for p in "$@"; do sv_pkg_installed "$p" && present+=("$p"); done
  [[ ${#present[@]} -eq 0 ]] && return 0
  if sv_dry; then sv_would "apt-get purge ${present[*]}"; return 0; fi
  sv_info "purging ${present[*]}"
  DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq "${present[@]}" >/dev/null 2>&1 \
    || sv_warn "could not purge: ${present[*]}"
  SV_MODULE_CHANGES=$((SV_MODULE_CHANGES + 1))
}

sv_unit_exists() {
  [[ $SV_HAS_SYSTEMD -eq 1 ]] || return 1
  systemctl list-unit-files "$1" >/dev/null 2>&1 && \
    systemctl list-unit-files "$1" 2>/dev/null | grep -q "^$1"
}

# systemctl reads /proc/1 to decide whether systemd is running. Inside a
# chroot on a systemd host that check passes while the unit database does not
# belong to us, and is-active then answers for units that do not exist here.
# Requiring the unit file keeps the answer honest.
sv_unit_active() {
  [[ $SV_HAS_SYSTEMD -eq 1 ]] || return 1
  sv_unit_exists "$1" || return 1
  systemctl is-active --quiet "$1" 2>/dev/null
}
sv_unit_enabled() {
  [[ $SV_HAS_SYSTEMD -eq 1 ]] || return 1
  systemctl is-enabled --quiet "$1" 2>/dev/null
}

sv_svc_enable() {
  local unit="$1"
  if [[ $SV_HAS_SYSTEMD -eq 0 ]]; then sv_debug "no systemd, not enabling $unit"; return 0; fi
  sv_unit_exists "$unit" || { sv_debug "$unit not installed"; return 1; }
  if sv_unit_enabled "$unit" && sv_unit_active "$unit"; then return 0; fi
  if sv_dry; then sv_would "systemctl enable --now $unit"; return 0; fi
  systemctl enable --now "$unit" >/dev/null 2>&1 || { sv_warn "could not start $unit"; return 1; }
  SV_MODULE_CHANGES=$((SV_MODULE_CHANGES + 1))
}

sv_svc_disable() {
  local unit="$1"
  [[ $SV_HAS_SYSTEMD -eq 1 ]] || return 0
  sv_unit_exists "$unit" || return 0
  sv_unit_active "$unit" || sv_unit_enabled "$unit" || return 0
  if sv_dry; then sv_would "systemctl disable --now $unit"; return 0; fi
  systemctl disable --now "$unit" >/dev/null 2>&1 || sv_warn "could not disable $unit"
  SV_MODULE_CHANGES=$((SV_MODULE_CHANGES + 1))
}

sv_svc_restart() {
  local unit="$1"
  [[ $SV_HAS_SYSTEMD -eq 1 ]] || return 0
  sv_unit_exists "$unit" || return 0
  if sv_dry; then sv_would "systemctl restart $unit"; return 0; fi
  systemctl restart "$unit" >/dev/null 2>&1 || { sv_warn "could not restart $unit"; return 1; }
}

sv_svc_reload() {
  local unit="$1"
  [[ $SV_HAS_SYSTEMD -eq 1 ]] || return 0
  sv_unit_exists "$unit" || return 0
  if sv_dry; then sv_would "systemctl reload $unit"; return 0; fi
  systemctl reload "$unit" >/dev/null 2>&1 || systemctl restart "$unit" >/dev/null 2>&1 \
    || { sv_warn "could not reload $unit"; return 1; }
}

# The sshd unit is called ssh on Debian and Ubuntu, sshd elsewhere, and newer
# Ubuntu uses socket activation where reloading the service does nothing.
sv_sshd_unit() {
  if sv_unit_exists ssh.service; then printf 'ssh.service'
  elif sv_unit_exists sshd.service; then printf 'sshd.service'
  else printf 'ssh.service'; fi
}

sv_sshd_socket_activated() {
  [[ $SV_HAS_SYSTEMD -eq 1 ]] || return 1
  sv_unit_exists ssh.socket && sv_unit_enabled ssh.socket
}


# --------------------------------------------------------------------------
# 5. helpers: files and backups
# --------------------------------------------------------------------------

#
# Nothing here writes to a file without first copying it into
# /var/backups/securevps/<run id>/ and appending a line to that run's
# manifest. "securevps.sh revert" replays a manifest backwards.

sv_run_init() {
  sv_dry && return 0
  SV_RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
  SV_BACKUP_DIR="$SV_BACKUP_ROOT/$SV_RUN_ID"
  SV_MANIFEST="$SV_BACKUP_DIR/manifest.tsv"
  mkdir -p "$SV_BACKUP_DIR/files" "$SV_STATE_DIR"
  chmod 0700 "$SV_BACKUP_ROOT" "$SV_BACKUP_DIR" "$SV_STATE_DIR"
  : >"$SV_MANIFEST"
  chmod 0600 "$SV_MANIFEST"
  printf '%s\t%s\t%s\n' "# securevps $SV_VERSION" "$SV_RUN_ID" "$(date -u +%FT%TZ)" >"$SV_BACKUP_DIR/run.info"
  ln -sfn "$SV_RUN_ID" "$SV_BACKUP_ROOT/latest"
}

sv_record() {
  sv_dry && return 0
  [[ -n "$SV_MANIFEST" ]] || return 0
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "${4:-}" >>"$SV_MANIFEST"
}

# Copy a file into the run's backup tree and return the stored name.
sv_backup_file() {
  local module="$1" path="$2"
  sv_bool core.backup || { printf ''; return 0; }
  sv_dry && { printf ''; return 0; }
  [[ -n "$SV_BACKUP_DIR" ]] || { printf ''; return 0; }
  local stored="${path//\//__}"
  local dest="$SV_BACKUP_DIR/files/$stored"
  if [[ ! -e "$dest" ]]; then
    cp -a --no-preserve=links "$path" "$dest" 2>/dev/null || cp -a "$path" "$dest"
  fi
  printf '%s' "$stored"
}

sv_show_diff() {
  local path="$1" new="$2"
  sv_quiet || sv_is_json && return 0
  if [[ -f "$path" ]] && sv_has_cmd diff; then
    diff -u --label "$path (now)" --label "$path (proposed)" "$path" "$new" \
      | sed 's/^/    /' || true
  else
    printf '    %s\n' "new file $path:"
    sed 's/^/      /' "$new"
  fi
}

# sv_write_file <module> <path> <mode> < content
# Sets SV_CHANGED to 1 when the file's content or mode actually changed.
sv_write_file() {
  local module="$1" path="$2" mode="${3:-0644}"
  local tmp; tmp="$(mktemp)"
  cat >"$tmp"
  SV_CHANGED=0

  if [[ -f "$path" ]] && cmp -s "$tmp" "$path"; then
    local cur; cur="$(stat -c '%a' "$path" 2>/dev/null || echo "")"
    if [[ "$cur" == "${mode#0}" || "$cur" == "$mode" ]]; then
      sv_debug "$path already correct"
      rm -f "$tmp"; return 0
    fi
  fi

  if sv_dry; then
    sv_would "write $path (mode $mode)"
    sv_show_diff "$path" "$tmp"
    rm -f "$tmp"; SV_CHANGED=1; return 0
  fi

  local dir; dir="$(dirname "$path")"
  if [[ ! -d "$dir" ]]; then
    mkdir -p "$dir"
    sv_record create "$module" "$dir" ""
  fi

  if [[ -e "$path" ]]; then
    local stored; stored="$(sv_backup_file "$module" "$path")"
    sv_record modify "$module" "$path" "$stored"
  else
    sv_record create "$module" "$path" ""
  fi

  install -m "$mode" "$tmp" "$path"
  rm -f "$tmp"
  SV_CHANGED=1
  SV_MODULE_CHANGES=$((SV_MODULE_CHANGES + 1))
  sv_debug "wrote $path"
}

# sv_write_gen <module> <path> <mode> <generator...>
# The generator writes the intended content to stdout. This wrapper exists
# because piping into sv_write_file would run it in a subshell, where the
# SV_CHANGED flag it sets could never reach the caller.
# The timer half of a scheduled job. The service half differs enough between
# callers to be worth writing out; this does not.
sv_timer_unit() {
  local module="$1" name="$2" description="$3" schedule="$4"
  sv_write_file "$module" "/etc/systemd/system/$name.timer" 0644 <<EOF
$(sv_managed_header)
[Unit]
Description=$description

[Timer]
OnCalendar=$schedule
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF
}

sv_write_gen() {
  local module="$1" path="$2" mode="$3"; shift 3
  local tmp; tmp="$(mktemp)"
  "$@" >"$tmp"
  sv_write_file "$module" "$path" "$mode" <"$tmp"
  rm -f "$tmp"
}

# Delete a file, keeping a copy so revert can put it back.
sv_remove_file() {
  local module="$1" path="$2"
  SV_CHANGED=0
  [[ -e "$path" ]] || return 0
  if sv_dry; then sv_would "remove $path"; SV_CHANGED=1; return 0; fi
  local stored; stored="$(sv_backup_file "$module" "$path")"
  sv_record delete "$module" "$path" "$stored"
  rm -f "$path"
  SV_CHANGED=1
  SV_MODULE_CHANGES=$((SV_MODULE_CHANGES + 1))
}

# Set "key<sep>value" in a file we do not own, such as /etc/login.defs.
# Replaces the first uncommented match, appends when there is none.
sv_set_kv() {
  local module="$1" path="$2" key="$3" value="$4" sep="${5:- }"
  SV_CHANGED=0
  [[ -f "$path" ]] || { sv_debug "$path missing, skipping $key"; return 0; }
  local current
  current="$(grep -E "^[[:space:]]*${key}([[:space:]]|=)" "$path" | head -1 || true)"
  local desired="${key}${sep}${value}"
  [[ "$current" == "$desired" ]] && return 0

  local tmp; tmp="$(mktemp)"
  if [[ -n "$current" ]]; then
    awk -v k="$key" -v line="$desired" '
      BEGIN { done = 0 }
      {
        if (!done && $0 ~ "^[[:space:]]*" k "([[:space:]]|=)") { print line; done = 1 }
        else print
      }
    ' "$path" >"$tmp"
  else
    cat "$path" >"$tmp"
    printf '%s\n' "$desired" >>"$tmp"
  fi

  if sv_dry; then
    sv_would "set $key in $path"
    sv_show_diff "$path" "$tmp"
    rm -f "$tmp"; SV_CHANGED=1; return 0
  fi

  local stored; stored="$(sv_backup_file "$module" "$path")"
  sv_record modify "$module" "$path" "$stored"
  local mode; mode="$(stat -c '%a' "$path")"
  install -m "$mode" "$tmp" "$path"
  rm -f "$tmp"
  SV_CHANGED=1
  SV_MODULE_CHANGES=$((SV_MODULE_CHANGES + 1))
}

# Run a config validator against a candidate file. On failure the caller is
# expected to abort its module rather than reload a broken service.
sv_validate() {
  local label="$1"; shift
  sv_dry && return 0
  if "$@" >/dev/null 2>&1; then
    sv_debug "$label validated"
    return 0
  fi
  sv_err "$label failed validation:"
  "$@" 2>&1 | sed 's/^/    /' >&2 || true
  return 1
}

# Put a file back from a manifest line.
sv_revert_entry() {
  local action="$1" path="$3" stored="$4" backup_dir="$5"
  case "$action" in
    modify|delete)
      if [[ -n "$stored" && -e "$backup_dir/files/$stored" ]]; then
        if sv_dry; then sv_would "restore $path"; return 0; fi
        install -m "$(stat -c '%a' "$backup_dir/files/$stored")" \
          "$backup_dir/files/$stored" "$path"
        sv_ok "restored $path"
      else
        sv_warn "no backup stored for $path, leaving it alone"
      fi
      ;;
    create)
      if [[ -e "$path" ]]; then
        if sv_dry; then sv_would "delete $path"; return 0; fi
        if [[ -d "$path" ]]; then rmdir "$path" 2>/dev/null || sv_debug "$path not empty, kept"
        else rm -f "$path"; sv_ok "removed $path"; fi
      fi
      ;;
  esac
}


# --------------------------------------------------------------------------
# 6. helpers: scan reporting
# --------------------------------------------------------------------------

sv_check() {
  local status="$1" module="$2" id="$3" message="$4"
  case "$status" in
    pass) SV_SCAN_PASS=$((SV_SCAN_PASS + 1)) ;;
    fail) SV_SCAN_FAIL=$((SV_SCAN_FAIL + 1)) ;;
    warn) SV_SCAN_WARN=$((SV_SCAN_WARN + 1)) ;;
    skip) SV_SCAN_SKIP=$((SV_SCAN_SKIP + 1)) ;;
  esac

  if sv_is_json; then
    SV_SCAN_JSON+=("$(printf '{"module":"%s","id":"%s","status":"%s","message":"%s"}' \
      "$module" "$id" "$status" "$(sv_json_escape "$message")")")
    return 0
  fi

  sv_quiet && [[ "$status" == "pass" || "$status" == "skip" ]] && return 0
  local mark
  case "$status" in
    pass) mark="${C_GREEN}pass${C_RESET}" ;;
    fail) mark="${C_RED}FAIL${C_RESET}" ;;
    warn) mark="${C_YELLOW}warn${C_RESET}" ;;
    skip) mark="${C_DIM}skip${C_RESET}" ;;
  esac
  printf '  %s  %-28s %s\n' "$mark" "$module.$id" "$message"
}

# Run a command and look for a fixed string in its output.
sv_grep_cmd() {
  local pattern="$1"; shift
  "$@" 2>/dev/null | grep -qF -- "$pattern"
}

# Invert a command's status, so a check can read as the good state.
sv_not() { ! "$@" >/dev/null 2>&1; }

sv_root_password_locked() {
  passwd -S root 2>/dev/null | awk '{print $2}' | grep -qE '^(L|LK)$'
}

sv_json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

# Pass when the command succeeds. The two messages describe the good and the
# bad state, because "no warning banner before login" is more use than a
# negated restatement of the check.
sv_verdict() {
  local module="$1" id="$2" good="$3" bad="$4"; shift 4
  if "$@" >/dev/null 2>&1; then sv_check pass "$module" "$id" "$good"
  else sv_check fail "$module" "$id" "$bad"; fi
}

# Pass when a value is one of the accepted ones.
sv_expect() {
  local module="$1" id="$2" label="$3" got="$4"; shift 4
  local want
  for want in "$@"; do
    if [[ "$got" == "$want" ]]; then
      sv_check pass "$module" "$id" "$label is $got"
      return 0
    fi
  done
  sv_check fail "$module" "$id" "$label is ${got:-unset}, wanted ${*// / or }"
  return 0
}

# Read one effective sshd setting. Empty when sshd cannot be queried.
sv_sshd_get() {
  sshd -T 2>/dev/null | awk -v k="${1,,}" '$1==k {$1=""; sub(/^ /,""); print; exit}'
}


# --------------------------------------------------------------------------
# 7. settings
# --------------------------------------------------------------------------

# Every setting lives in CFG under a "<module>.<name>" key, and every one of
# them is a command line flag. Booleans are always named positively, so
# --docker-daemon-config turns a thing on and --no-docker-daemon-config turns
# it off. When a single module runs its own prefix is optional, so
# "securevps.sh ssh --port 2222" and "securevps.sh harden --ssh-port 2222"
# set the same thing.

declare -A CFG=()
declare -A OPT_TYPE=()
declare -A OPT_HELP=()
declare -a OPT_ORDER=()

defopt() {
  local key="$1" type="$2" default="$3" help="$4"
  CFG["$key"]="$default"
  OPT_TYPE["$key"]="$type"
  OPT_HELP["$key"]="$help"
  OPT_ORDER+=("$key")
}

sv_get() { printf '%s' "${CFG[$1]-}"; }
sv_bool() { [[ "${CFG[$1]-}" == "true" ]]; }
sv_int() { printf '%s' "${CFG[$1]-0}"; }

sv_set() {
  local key="$1" value="$2"
  [[ -n "${OPT_TYPE[$key]-}" ]] || sv_die "unknown setting: $key"
  case "${OPT_TYPE[$key]}" in
    bool)
      case "${value,,}" in
        true|yes|on|1) value=true ;;
        false|no|off|0) value=false ;;
        *) sv_die "setting $key takes true or false, got '$value'" ;;
      esac
      ;;
    int)
      [[ "$value" =~ ^[0-9]+$ ]] || sv_die "setting $key takes a number, got '$value'"
      ;;
  esac
  CFG["$key"]="$value"
}

# --- core -----------------------------------------------------------------
defopt core.dry-run  bool false    "print every change as a diff, write nothing"
defopt core.yes      bool false    "answer every prompt with yes"
defopt core.verbose  bool false    "log what each check is doing"
defopt core.quiet    bool false    "only errors"
defopt core.json     bool false    "machine-readable output, mainly for scan"
defopt core.profile  str  core     "core, minimal or standard"
defopt core.backup   bool true     "back up every file before editing it"
defopt core.only     str  ""       "comma-separated modules to run"
defopt core.skip     str  ""       "comma-separated modules to leave out"
defopt core.force    bool false    "carry on past safety checks that would normally stop the run"

# --- updates --------------------------------------------------------------
defopt updates.upgrade      bool true     "run a full package upgrade now"
defopt updates.auto         bool true     "install and enable unattended-upgrades"
defopt updates.scope        str  security "which pocket auto-updates draw from: security or all"
defopt updates.autoremove   bool true     "remove orphaned packages and old kernels"
defopt updates.auto-reboot  str  ""       "reboot automatically at HH:MM when a patch needs it"
defopt updates.needrestart  bool true     "restart services automatically after a library patch"

# --- user -----------------------------------------------------------------
defopt user.create         bool true     "create a non-root administrator"
defopt user.name           str  deploy   "name of that administrator"
defopt user.ssh-key        str  ""       "public key or path to one, defaults to root's authorized_keys"
defopt user.shell          str  /bin/bash "login shell for the new user"
defopt user.lock-root      bool true     "lock root's password, key login still works"
defopt user.sudo-nopasswd  bool false    "let the admin sudo without a password"
defopt user.umask          str  027      "default umask for login shells"
defopt user.restrict-su    bool true     "only the sudo group may run su"

# --- ssh ------------------------------------------------------------------
defopt ssh.port              int  22    "port sshd listens on"
defopt ssh.password-auth     bool false "allow password logins"
defopt ssh.permit-root       str  no    "PermitRootLogin: no, prohibit-password or yes"
defopt ssh.allow-users       str  ""    "comma-separated AllowUsers list"
defopt ssh.allow-groups      str  sudo  "comma-separated AllowGroups list, empty to omit"
defopt ssh.max-auth-tries    int  3     "MaxAuthTries"
defopt ssh.login-grace       int  30    "LoginGraceTime in seconds"
defopt ssh.client-alive      int  300   "ClientAliveInterval in seconds"
defopt ssh.tcp-forwarding    bool false "allow TCP forwarding, needed for SSH tunnels to admin UIs"
defopt ssh.agent-forwarding  bool false "allow agent forwarding"
defopt ssh.x11-forwarding    bool false "allow X11 forwarding"
defopt ssh.gateway-ports     bool false "allow remote hosts to use forwarded ports"
defopt ssh.modern-crypto     bool true  "restrict KEX, ciphers and MACs to the modern set"
defopt ssh.regen-hostkeys    bool true  "drop obsolete host keys and make sure ed25519 and RSA 4096 exist"
defopt ssh.drop-ecdsa        bool false "also remove the ECDSA host key, changes the fingerprint clients see"
defopt ssh.moduli            bool true  "remove DH moduli smaller than 3072 bits"
defopt ssh.disable-pam       bool false "UsePAM no, see the catalog before turning this on"
defopt ssh.rollback-timeout  int  300   "seconds before an unconfirmed sshd change rolls back, 0 to disable"

# --- firewall -------------------------------------------------------------
defopt firewall.backend     str  auto  "ufw, nftables or auto"
defopt firewall.enable      bool true  "turn the firewall on"
defopt firewall.allow       str  ""    "extra ports to open, e.g. 80,443,25/tcp"
defopt firewall.allow-from  str  ""    "source-restricted rules, e.g. 10.0.0.0/8:5432"
defopt firewall.ssh-limit   bool true  "rate-limit new SSH connections"
defopt firewall.ipv6        bool true  "mirror every rule onto IPv6"
defopt firewall.log-level   str  low   "off, low, medium, high or full"
defopt firewall.block-ping  bool false "drop inbound ICMP echo requests"

# --- docker ---------------------------------------------------------------
defopt docker.firewall-fix       bool true  "stop published container ports bypassing the firewall"
defopt docker.allow-from         str  ""    "extra CIDRs allowed to reach published ports"
defopt docker.allow-published    str  ""    "container ports to expose publicly anyway, e.g. 80,443"
defopt docker.daemon-config      bool true  "manage /etc/docker/daemon.json"
defopt docker.no-new-privileges  bool true  "block setuid privilege escalation inside containers"
defopt docker.icc                bool true  "allow container-to-container traffic on the default bridge"
defopt docker.live-restore       bool true  "keep containers running across daemon restarts"
defopt docker.userland-proxy     bool false "use the userland proxy instead of iptables hairpin NAT"
defopt docker.log-max-size       str  10m   "per-container log file size before rotation"
defopt docker.log-max-file       int  3     "how many rotated log files to keep"
defopt docker.only-rules         bool false "reapply the DOCKER-USER rules and nothing else"

# --- bruteforce -----------------------------------------------------------
defopt bruteforce.engine          str  fail2ban "fail2ban, crowdsec or none"
defopt bruteforce.maxretry        int  5        "failures before a ban"
defopt bruteforce.findtime        str  10m      "window those failures are counted in"
defopt bruteforce.bantime         str  1h       "how long a ban lasts"
defopt bruteforce.recidive        bool true     "ban repeat offenders for a week"
defopt bruteforce.aggressive      bool true     "match probes that never reach a password prompt"
defopt bruteforce.ignore-ip       str  ""       "never ban these addresses"
defopt bruteforce.auto-ignore-ip  bool true     "also never ban the address you are connected from"

# --- sysctl ---------------------------------------------------------------
defopt sysctl.network       bool true  "network stack hardening"
defopt sysctl.kernel        bool true  "kernel information and feature restrictions"
defopt sysctl.filesystem    bool true  "link protections and core dump restrictions"
defopt sysctl.ipv6          bool true  "keep IPv6 enabled"
defopt sysctl.ip-forward    str  auto  "on, off or auto, which keeps it on when Docker is present"
defopt sysctl.ptrace-scope  int  1     "yama ptrace_scope, 2 blocks debuggers entirely"
defopt sysctl.userns        bool true  "keep unprivileged user namespaces, containers need them"

# --- kmodules -------------------------------------------------------------
defopt kmodules.filesystems  bool true  "blacklist cramfs, freevxfs, jffs2, hfs, hfsplus, udf"
defopt kmodules.protocols    bool true  "blacklist dccp, sctp, rds, tipc"
defopt kmodules.extra        str  ""    "extra modules to blacklist, comma separated"

# --- mounts ---------------------------------------------------------------
# /dev/shm is the one that is pure win: nothing legitimate executes or makes
# device nodes there, and it is a favourite staging area for exploits. /tmp
# and /var/tmp are opt-in because package installers and image builds do run
# scripts out of them.
defopt mounts.dev-shm     bool true  "nodev,nosuid,noexec on /dev/shm"
defopt mounts.var-tmp     bool false "nodev,nosuid,noexec on /var/tmp"
defopt mounts.tmp         bool false "make /tmp a tmpfs with nodev,nosuid"
defopt mounts.noexec-tmp  bool false "also noexec on /tmp, breaks some installers"

# --- pam ------------------------------------------------------------------
defopt pam.pwquality        bool true "enforce password complexity"
defopt pam.min-length       int  12   "minimum password length"
defopt pam.min-classes      int  3    "minimum character classes"
defopt pam.remember         int  5    "how many old passwords cannot be reused"
defopt pam.faillock         bool true "lock an account after repeated failures"
defopt pam.faillock-deny    int  5    "failures before the lock"
defopt pam.faillock-unlock  int  900  "seconds before it unlocks"
defopt pam.login-defs       bool true "manage /etc/login.defs"
defopt pam.pass-max-days    int  365  "password maximum age"
defopt pam.tmout            int  0    "idle shell timeout in seconds, 0 to leave shells alone"

# --- services -------------------------------------------------------------
defopt services.disable  bool true "stop and disable services a VPS rarely needs"
defopt services.purge    bool false "also uninstall them"
defopt services.keep     str  ""    "services to leave alone, comma separated"
defopt services.extra    str  ""    "extra services to disable, comma separated"

# --- time -----------------------------------------------------------------
defopt time.chrony      bool true "install chrony rather than relying on timesyncd"
defopt time.timezone    str  UTC  "system timezone"
defopt time.ntp-server  str  ""   "override the NTP pool"

# --- logging --------------------------------------------------------------
defopt logging.journald           bool true    "persistent journal with a size cap"
defopt logging.journal-max        str  1G      "disk the journal may use"
defopt logging.journal-retention  str  1month  "how long to keep journal entries"
defopt logging.auditd             bool true    "install and enable auditd"
defopt logging.audit-rules        str  light   "light, cis or none"
defopt logging.remote-syslog      str  ""      "forward syslog to host:port"

# --- apparmor -------------------------------------------------------------
defopt apparmor.enforce  bool true "put every loaded profile into enforce mode"

# --- banner ---------------------------------------------------------------
defopt banner.issue  bool true "warning banner in /etc/issue and /etc/issue.net"
defopt banner.motd   bool true "replace the dynamic motd"
defopt banner.file   str  ""   "read the banner text from this file instead"

# --- integrity ------------------------------------------------------------
defopt integrity.enable    bool false "install AIDE and build its database"
defopt integrity.schedule  str  daily "systemd OnCalendar expression for the check"

# --- mfa ------------------------------------------------------------------
defopt mfa.enable       bool false "require a TOTP code in addition to the SSH key"
defopt mfa.exempt-user   str  ""   "users that keep key-only login, e.g. a deploy account"

# --- vpn ------------------------------------------------------------------
defopt vpn.provider           str  none  "none, wireguard or tailscale"
defopt vpn.tailscale-authkey  str  ""    "Tailscale auth key for unattended enrolment"
defopt vpn.wg-port            int  51820 "WireGuard listen port"
defopt vpn.ssh-vpn-only       bool false "restrict SSH to the VPN interface, closes the public port"

# --- alerts ---------------------------------------------------------------
defopt alerts.login-alert  bool false "notify on every interactive SSH login"
defopt alerts.email        str  ""    "address for notifications"
defopt alerts.webhook      str  ""    "URL to POST notifications to"

# --- backup ---------------------------------------------------------------
defopt backup.enable         bool false "install restic and a scheduled backup job"
defopt backup.repo           str  ""    "restic repository URL"
defopt backup.password-file  str  ""    "file holding the repository password"
defopt backup.schedule       str  daily "systemd OnCalendar expression"


# --------------------------------------------------------------------------
# 8. commands
# --------------------------------------------------------------------------

#
# Each hardening step <m> is two functions:
#
#   <m>_apply   make the changes
#   <m>_scan    report on them, one sv_check per finding
#
# Its one-line summary lives in MODULE_DESC at the top of the file, and the
# block above each pair says what it changes and why.
#
# A step never calls exit. It returns non-zero to mark itself failed and lets
# the rest of the run carry on.

# Append a line to a file we do not own, if no line matching <regex> is there.
sv_ensure_line() {
  local module="$1" path="$2" line="$3" regex="${4:-}"
  SV_CHANGED=0
  [[ -f "$path" ]] || { sv_debug "$path missing, not adding line"; return 0; }
  # shellcheck disable=SC2016  # a sed program, not a shell expansion
  [[ -z "$regex" ]] && regex="$(printf '%s' "$line" | sed 's/[][\.*^$(){}?+|/]/\\&/g')"
  grep -qE "$regex" "$path" && return 0
  if sv_dry; then sv_would "append to $path: $line"; SV_CHANGED=1; return 0; fi
  local stored; stored="$(sv_backup_file "$module" "$path")"
  sv_record modify "$module" "$path" "$stored"
  printf '%s\n' "$line" >>"$path"
  SV_CHANGED=1
  SV_MODULE_CHANGES=$((SV_MODULE_CHANGES + 1))
}

sv_managed_header() {
  cat <<EOF
# Managed by securevps.sh $SV_VERSION. Edits here are overwritten on the next run.
# Change the setting with a --flag instead. See securevps.sh help.
EOF
}

# ==========================================================================
# updates - security patches, applied now and automatically
# ==========================================================================
#
# Installs what is pending, then turns on unattended-upgrades restricted to
# the security pocket so it keeps happening without you. needrestart is set
# to restart services by itself, which matters more than it sounds: patching
# a library does nothing for the processes that already mapped the old one.
#
# Automatic reboots stay off. --updates-auto-reboot 04:00 turns them on.


updates_apply() {
  sv_header "updates"

  if sv_bool updates.upgrade; then
    sv_apt_update
    if sv_dry; then
      sv_would "apt-get upgrade"
    else
      sv_info "upgrading installed packages, this can take a few minutes"
      DEBIAN_FRONTEND=noninteractive apt-get -y -qq \
        -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
        upgrade >/dev/null 2>&1 || sv_warn "apt-get upgrade reported errors"
      sv_ok "packages upgraded"
    fi
  else
    sv_skip "upgrade disabled"
  fi

  if sv_bool updates.autoremove && ! sv_dry; then
    DEBIAN_FRONTEND=noninteractive apt-get -y -qq autoremove --purge >/dev/null 2>&1 || true
  fi

  if sv_bool updates.auto; then
    sv_pkg_install unattended-upgrades apt-listchanges || true

    local origins reboot_line="Unattended-Upgrade::Automatic-Reboot \"false\";"
    local reboot_time; reboot_time="$(sv_get updates.auto-reboot)"
    if [[ -n "$reboot_time" ]]; then
      reboot_line="Unattended-Upgrade::Automatic-Reboot \"true\";
Unattended-Upgrade::Automatic-Reboot-WithUsers \"false\";
Unattended-Upgrade::Automatic-Reboot-Time \"$reboot_time\";"
    fi

    # shellcheck disable=SC2016  # unattended-upgrades expands these itself
    if [[ "$SV_OS_ID" == ubuntu ]]; then
      origins='        "${distro_id}:${distro_codename}-security";
        "${distro_id}ESMApps:${distro_codename}-apps-security";
        "${distro_id}ESM:${distro_codename}-infra-security";'
      [[ "$(sv_get updates.scope)" == all ]] && origins="$origins
        \"\${distro_id}:\${distro_codename}\";
        \"\${distro_id}:\${distro_codename}-updates\";"
    else
      origins='        "origin=Debian,codename=${distro_codename},label=Debian-Security";
        "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";'
      [[ "$(sv_get updates.scope)" == all ]] && origins="$origins
        \"origin=Debian,codename=\${distro_codename},label=Debian\";
        \"origin=Debian,codename=\${distro_codename}-updates,label=Debian\";"
    fi

    sv_write_file updates /etc/apt/apt.conf.d/99securevps-unattended 0644 <<EOF
$(sv_managed_header)

Unattended-Upgrade::Allowed-Origins {
$origins
};

Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::MinimalSteps "true";
$reboot_line
EOF

    sv_write_file updates /etc/apt/apt.conf.d/99securevps-periodic 0644 <<EOF
$(sv_managed_header)

APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

    sv_svc_enable unattended-upgrades.service || true
    sv_svc_enable apt-daily.timer || true
    sv_svc_enable apt-daily-upgrade.timer || true
    sv_ok "unattended $(sv_get updates.scope) updates enabled"
    [[ -n "$reboot_time" ]] && sv_note "The server will reboot itself at $reboot_time when a patch requires it."
  else
    sv_skip "automatic updates disabled"
  fi

  if sv_bool updates.needrestart; then
    if sv_pkg_install needrestart; then
      sv_write_file updates /etc/needrestart/conf.d/99-securevps.conf 0644 <<EOF
$(sv_managed_header)
# Restart patched services without asking. Without this a security update
# leaves the vulnerable library mapped into every running process.
\$nrconf{restart} = 'a';
\$nrconf{kernelhints} = 0;
EOF
      sv_ok "services restart automatically after library patches"
    fi
  fi

  [[ -f /var/run/reboot-required ]] && SV_REBOOT_REQUIRED=1
  return 0
}

updates_scan() {
  sv_verdict updates unattended-upgrades \
    "unattended-upgrades installed" "unattended-upgrades not installed" \
    sv_pkg_installed unattended-upgrades

  if [[ -f /etc/apt/apt.conf.d/99securevps-periodic ]] \
     && grep -q 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/99securevps-periodic 2>/dev/null; then
    sv_check pass updates periodic "automatic upgrades scheduled"
  elif grep -rqs 'APT::Periodic::Unattended-Upgrade "1"' /etc/apt/apt.conf.d/ 2>/dev/null; then
    sv_check pass updates periodic "automatic upgrades scheduled elsewhere in apt.conf.d"
  else
    sv_check fail updates periodic "automatic upgrades not scheduled"
  fi

  local pending=0
  if sv_has_cmd apt-get; then
    pending="$(apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null \
      | grep -c '^Inst.*security' || true)"
  fi
  if [[ "${pending:-0}" -gt 0 ]]; then
    sv_check fail updates pending "$pending security updates waiting to be installed"
  else
    sv_check pass updates pending "no pending security updates"
  fi

  if [[ -f /var/run/reboot-required ]]; then
    sv_check warn updates reboot "a reboot is needed to finish applying updates"
  else
    sv_check pass updates reboot "no reboot pending"
  fi
}

# ==========================================================================
# user - a non-root administrator, and root locked down behind it
# ==========================================================================
#
# Creates the account, puts it in sudo, copies root's authorized keys across,
# and locks root's password. That last step is guarded: it checks some
# non-root account really has a key and sudo rights first. A script that
# locks root on a box with no other way in has not hardened anything.

user_collect_keys() {
  local src; src="$(sv_get user.ssh-key)"
  if [[ -n "$src" ]]; then
    if [[ -f "$src" ]]; then cat "$src"
    else printf '%s\n' "$src"; fi
    return 0
  fi
  local f
  for f in /root/.ssh/authorized_keys /root/.ssh/authorized_keys2; do
    [[ -s "$f" ]] || continue
    # shellcheck disable=SC2016  # a grep pattern, not a shell expansion
    grep -E '^(ssh|ecdsa|sk-)' "$f" || true
  done
}

sv_user_key_count() {
  local home="$1"
  [[ -s "$home/.ssh/authorized_keys" ]] || { printf 0; return 0; }
  grep -cE '^[[:space:]]*(ssh-|ecdsa-|sk-)' "$home/.ssh/authorized_keys" 2>/dev/null || printf 0
}

# True when the account can get past sudo's password prompt: it has a usable
# password, or a NOPASSWD rule. A fresh useradd has neither, and an admin who
# can log in but never sudo is no admin once root is locked.
sv_user_can_sudo() {
  local acct="$1" hash
  hash="$(getent shadow "$acct" 2>/dev/null | cut -d: -f2)"
  [[ -n "$hash" && "$hash" != '!'* && "$hash" != '*'* ]] && return 0
  sv_has_cmd sudo && sudo -l -U "$acct" 2>/dev/null | grep -q NOPASSWD
}

user_apply() {
  sv_header "user"
  local name; name="$(sv_get user.name)"

  if sv_bool user.create; then
    local home="/home/$name"
    if id -u "$name" >/dev/null 2>&1; then
      home="$(getent passwd "$name" | cut -d: -f6)"
      sv_skip "user $name already exists"
    elif sv_dry; then
      sv_would "useradd -m -s $(sv_get user.shell) $name, add to sudo group"
    else
      useradd -m -s "$(sv_get user.shell)" "$name"
      usermod -aG sudo "$name"
      passwd -l "$name" >/dev/null 2>&1 || true
      SV_MODULE_CHANGES=$((SV_MODULE_CHANGES + 1))
      sv_ok "created $name and added it to the sudo group"
    fi

    if ! sv_dry && id -u "$name" >/dev/null 2>&1; then
      id -nG "$name" | tr ' ' '\n' | grep -qx sudo || {
        usermod -aG sudo "$name"; sv_ok "added $name to the sudo group"
      }

      local keys; keys="$(user_collect_keys)"
      if [[ -n "${keys//[[:space:]]/}" ]]; then
        mkdir -p "$home/.ssh"
        chmod 0700 "$home/.ssh"
        local existing="" merged
        [[ -f "$home/.ssh/authorized_keys" ]] && existing="$(cat "$home/.ssh/authorized_keys")"
        merged="$(printf '%s\n%s\n' "$existing" "$keys" | grep -vE '^[[:space:]]*$' | sort -u)"
        sv_write_file user "$home/.ssh/authorized_keys" 0600 <<<"$merged"
        chown -R "$name:$name" "$home/.ssh"
        [[ $SV_CHANGED -eq 1 ]] && sv_ok "installed $(printf '%s\n' "$merged" | wc -l) key(s) for $name"
      else
        sv_warn "no public key found for $name. Add one before locking root out:"
        sv_warn "  ssh-copy-id $name@$(hostname -I 2>/dev/null | awk '{print $1}')"
      fi

      # useradd leaves the password locked, and sudo asks for one. Ask now
      # while there is a person at the keyboard.
      if ! sv_bool user.sudo-nopasswd && ! sv_user_can_sudo "$name"; then
        if [[ -t 0 ]] && ! sv_bool core.yes; then
          sv_info "sudo will ask $name for a password. Set one now."
          passwd "$name" </dev/tty || sv_warn "no password set for $name"
        fi
        sv_user_can_sudo "$name" || sv_note "$name has no password, so sudo will ask for one it cannot answer. Run: passwd $name (or use --user-sudo-nopasswd)."
      fi
    fi

    if sv_bool user.sudo-nopasswd; then
      sv_write_file user "/etc/sudoers.d/90-securevps-$name" 0440 \
        <<<"$name ALL=(ALL) NOPASSWD:ALL"
      if [[ $SV_CHANGED -eq 1 ]] && ! sv_dry; then
        if ! sv_validate "sudoers" visudo -cf "/etc/sudoers.d/90-securevps-$name"; then
          rm -f "/etc/sudoers.d/90-securevps-$name"
          sv_err "generated sudoers file was rejected, removed it"
          return 1
        fi
        sv_ok "$name may sudo without a password"
      fi
    fi
  else
    sv_skip "not creating an administrator"
  fi

  # umask for login shells.
  sv_write_file user /etc/profile.d/99-securevps-umask.sh 0644 <<EOF
$(sv_managed_header)
umask $(sv_get user.umask)
EOF
  sv_set_kv user /etc/login.defs UMASK "$(sv_get user.umask)" $'\t'

  if sv_bool user.restrict-su; then
    sv_ensure_line user /etc/pam.d/su \
      "auth       required   pam_wheel.so use_uid group=sudo" \
      '^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so'
    [[ $SV_CHANGED -eq 1 ]] && sv_ok "su restricted to the sudo group"
  fi

  # Locking root's password is the last thing, and only once a way back in
  # has been proven to exist.
  if sv_bool user.lock-root; then
    if user_root_lock_safe; then
      if sv_dry; then
        sv_would "passwd -l root"
      elif sv_root_password_locked; then
        sv_skip "root password already locked"
      else
        sv_record custom user "root-password-lock" ""
        passwd -l root >/dev/null
        SV_MODULE_CHANGES=$((SV_MODULE_CHANGES + 1))
        sv_ok "root password locked, key-based root login is unaffected"
      fi
    else
      sv_warn "not locking root: no other account can both log in and get past sudo yet"
      sv_note "root's password is still active. Give $(sv_get user.name) an SSH key and a password (passwd $(sv_get user.name)), then run: securevps.sh user"
      sv_dry || return 1
    fi
  fi
  return 0
}

# True when some non-root account has an SSH key, sudo rights, and a way past
# sudo's password prompt, so locking root cannot strand us.
user_root_lock_safe() {
  sv_bool core.force && return 0
  # A dry run has not created the administrator yet, so judge the plan, not
  # the current state.
  if sv_dry && sv_bool user.create && sv_bool user.sudo-nopasswd \
     && [[ -n "$(user_collect_keys)" ]]; then return 0; fi
  local candidate home
  while IFS=: read -r candidate _ uid _ _ home _; do
    [[ "$uid" -ge 1000 && "$uid" -lt 65534 ]] || continue
    [[ -d "$home" ]] || continue
    [[ "$(sv_user_key_count "$home")" -gt 0 ]] || continue
    id -nG "$candidate" 2>/dev/null | tr ' ' '\n' | grep -qxE 'sudo|admin' || continue
    sv_user_can_sudo "$candidate" || continue
    sv_debug "root lock is safe, $candidate has a key, sudo, and a way past the prompt"
    return 0
  done <<< "$(getent passwd)"
  return 1
}

user_scan() {
  local name; name="$(sv_get user.name)"
  if id -u "$name" >/dev/null 2>&1; then
    sv_check pass user admin "administrator $name exists"
    local home; home="$(getent passwd "$name" | cut -d: -f6)"
    if [[ "$(sv_user_key_count "$home")" -gt 0 ]]; then
      sv_check pass user admin-key "$name has an authorized SSH key"
    else
      sv_check fail user admin-key "$name has no authorized SSH key"
    fi
    if sv_user_can_sudo "$name"; then
      sv_check pass user admin-sudo "$name can get past sudo's password prompt"
    else
      sv_check warn user admin-sudo "$name has no password and no NOPASSWD rule, sudo will refuse"
    fi
  else
    sv_check warn user admin "administrator $name does not exist"
  fi

  sv_verdict user root-locked "root password is locked" "root password is not locked" \
    sv_root_password_locked

  local empty; empty="$(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null | tr '\n' ' ' || true)"
  if [[ -n "${empty// /}" ]]; then
    sv_check fail user empty-password "accounts with no password: $empty"
  else
    sv_check pass user empty-password "no accounts with an empty password"
  fi

  local dupuid0; dupuid0="$(awk -F: '($3==0 && $1!="root"){print $1}' /etc/passwd | tr '\n' ' ' || true)"
  if [[ -n "${dupuid0// /}" ]]; then
    sv_check fail user uid0 "extra accounts with UID 0: $dupuid0"
  else
    sv_check pass user uid0 "root is the only UID 0 account"
  fi

  local umask_now; umask_now="$(awk '/^UMASK/{print $2}' /etc/login.defs 2>/dev/null || true)"
  sv_expect user umask "login umask" "$umask_now" "$(sv_get user.umask)"
}

# ==========================================================================
# ssh - key-only sshd with modern crypto and a rollback timer
# ==========================================================================
#
# Password authentication off is the single most valuable line in the file.
# Everything else here is worth less than that one.
#
# Three things stop this locking you out: it refuses a config no account
# could log in through, it runs sshd -t before reloading and restores the
# backup if that fails, and it arms a timer that puts the old config back
# unless securevps.sh confirm runs from a second session.


readonly SV_SSHD_DROPIN="/etc/ssh/sshd_config.d/99-securevps.conf"
readonly SV_SSH_SOCKET_DROPIN="/etc/systemd/system/ssh.socket.d/99-securevps.conf"
readonly SV_SSH_ROLLBACK="/usr/local/sbin/securevps-ssh-rollback"

sv_onoff() { if sv_bool "$1"; then printf 'yes'; else printf 'no'; fi; }

# What sshd will insist on. The MFA module rewrites this to add a TOTP step.
ssh_auth_methods() {
  if sv_bool mfa.enable; then printf 'publickey,keyboard-interactive:pam'
  elif sv_bool ssh.password-auth; then printf 'any'
  else printf 'publickey'; fi
}

# Who is allowed in after this change, as an AllowUsers list.
ssh_allow_users() {
  local users; users="$(sv_get ssh.allow-users)"
  [[ "$(sv_get ssh.permit-root)" != "no" ]] && users="${users:+$users,}root"
  printf '%s' "${users//,/ }"
}

# Refuse to apply a config that nobody could log in through.
ssh_login_path_exists() {
  sv_bool core.force && return 0
  sv_bool ssh.password-auth && return 0

  local groups; groups="$(sv_get ssh.allow-groups)"
  local users; users="$(ssh_allow_users)"

  local acct home uid
  while IFS=: read -r acct _ uid _ _ home _; do
    [[ "$(sv_user_key_count "$home")" -gt 0 ]] || continue
    if [[ "$acct" == root ]]; then
      [[ "$(sv_get ssh.permit-root)" == "no" ]] && continue
    else
      [[ "$uid" -ge 1000 && "$uid" -lt 65534 ]] || continue
    fi
    # Must survive both allowlists.
    # shellcheck disable=SC2086  # $users is a deliberately split word list
    if [[ -n "$users" ]] && ! printf '%s\n' $users | grep -qx "$acct"; then continue; fi
    if [[ -n "$groups" ]]; then
      local g ok=0
      for g in ${groups//,/ }; do
        id -nG "$acct" 2>/dev/null | tr ' ' '\n' | grep -qx "$g" && { ok=1; break; }
      done
      [[ $ok -eq 1 ]] || continue
    fi
    sv_debug "login path exists via $acct"
    return 0
  done <<< "$(getent passwd)"
  return 1
}

ssh_render_config() {
  local port; port="$(sv_int ssh.port)"
  local users; users="$(ssh_allow_users)"
  local groups; groups="$(sv_get ssh.allow-groups)"

  sv_managed_header
  cat <<EOF

Port $port

# Authentication
PubkeyAuthentication yes
PasswordAuthentication $(sv_onoff ssh.password-auth)
KbdInteractiveAuthentication $(sv_onoff ssh.password-auth)
ChallengeResponseAuthentication $(sv_onoff ssh.password-auth)
PermitRootLogin $(sv_get ssh.permit-root)
PermitEmptyPasswords no
AuthenticationMethods $(ssh_auth_methods)
MaxAuthTries $(sv_int ssh.max-auth-tries)
MaxSessions 5
MaxStartups 10:30:60
LoginGraceTime $(sv_int ssh.login-grace)
EOF

  if sv_bool ssh.disable-pam; then
    printf '%s\n' "UsePAM no"
  else
    printf '%s\n' "UsePAM yes"
  fi
  [[ -n "$users" ]] && printf 'AllowUsers %s\n' "$users"
  [[ -n "$groups" ]] && printf 'AllowGroups %s\n' "${groups//,/ }"

  cat <<EOF

# Session
ClientAliveInterval $(sv_int ssh.client-alive)
ClientAliveCountMax 2
TCPKeepAlive no

# Forwarding
AllowTcpForwarding $(sv_onoff ssh.tcp-forwarding)
AllowAgentForwarding $(sv_onoff ssh.agent-forwarding)
X11Forwarding $(sv_onoff ssh.x11-forwarding)
GatewayPorts $(sv_onoff ssh.gateway-ports)
PermitTunnel no
AllowStreamLocalForwarding no

# Misc
IgnoreRhosts yes
HostbasedAuthentication no
PermitUserEnvironment no
PrintLastLog yes
Compression no
DebianBanner no
Banner /etc/issue.net
EOF

  if sv_bool ssh.modern-crypto; then
    cat <<'EOF'

# Crypto. Everything here is what OpenSSH 9 considers safe; the point of
# listing it is to drop the older algorithms kept for compatibility.
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256
PubkeyAcceptedAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,rsa-sha2-512,rsa-sha2-256
EOF
  fi
}

# Debian 10 and older have no Include line, so a drop-in would be ignored.
ssh_ensure_include() {
  grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' /etc/ssh/sshd_config && return 0
  sv_info "adding the sshd_config.d Include line, this sshd does not have one"
  if sv_dry; then sv_would "prepend Include to /etc/ssh/sshd_config"; return 0; fi
  local tmp; tmp="$(mktemp)"
  printf 'Include /etc/ssh/sshd_config.d/*.conf\n\n' >"$tmp"
  cat /etc/ssh/sshd_config >>"$tmp"
  local stored; stored="$(sv_backup_file ssh /etc/ssh/sshd_config)"
  sv_record modify ssh /etc/ssh/sshd_config "$stored"
  install -m 0644 "$tmp" /etc/ssh/sshd_config
  rm -f "$tmp"
}

ssh_hostkeys() {
  sv_bool ssh.regen-hostkeys || return 0
  local changed=0 k

  k=/etc/ssh/ssh_host_dsa_key
  if [[ -f "$k" ]]; then
    sv_remove_file ssh "$k"; sv_remove_file ssh "$k.pub"
    sv_warn "removed the DSA host key, no modern client can use it"
    changed=1
  fi

  k=/etc/ssh/ssh_host_ecdsa_key
  if sv_bool ssh.drop-ecdsa && [[ -f "$k" ]]; then
    sv_remove_file ssh "$k"; sv_remove_file ssh "$k.pub"
    sv_note "The ECDSA host key was removed. Clients that pinned it will warn once."
    changed=1
  fi

  if [[ ! -f /etc/ssh/ssh_host_ed25519_key ]]; then
    if sv_dry; then sv_would "generate an ed25519 host key"
    else
      ssh-keygen -q -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" -C "" </dev/null
      sv_record create ssh /etc/ssh/ssh_host_ed25519_key ""
      sv_ok "generated an ed25519 host key"
      changed=1
    fi
  fi

  if [[ -f /etc/ssh/ssh_host_rsa_key.pub ]]; then
    local bits
    bits="$(ssh-keygen -l -f /etc/ssh/ssh_host_rsa_key.pub 2>/dev/null | awk '{print $1}' || true)"
    if [[ "${bits:-0}" -lt 3072 ]]; then
      if sv_dry; then sv_would "regenerate the ${bits}-bit RSA host key at 4096 bits"
      else
        sv_remove_file ssh /etc/ssh/ssh_host_rsa_key
        sv_remove_file ssh /etc/ssh/ssh_host_rsa_key.pub
        ssh-keygen -q -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N "" -C "" </dev/null
        sv_warn "the RSA host key was only ${bits} bits and has been replaced"
        sv_note "The RSA host key changed. Clients that pinned it will warn on the next connection."
        changed=1
      fi
    fi
  fi

  [[ $changed -eq 1 ]] && SV_MODULE_CHANGES=$((SV_MODULE_CHANGES + 1))
  return 0
}

ssh_moduli() {
  sv_bool ssh.moduli || return 0
  [[ -f /etc/ssh/moduli ]] || return 0
  local weak; weak="$(awk '$1 !~ /^#/ && $5 < 3071' /etc/ssh/moduli 2>/dev/null | wc -l)"
  [[ "${weak:-0}" -eq 0 ]] && { sv_debug "no weak DH moduli"; return 0; }
  local tmp; tmp="$(mktemp)"
  awk '$1 ~ /^#/ || $5 >= 3071' /etc/ssh/moduli >"$tmp"
  if [[ "$(grep -cv '^#' "$tmp")" -lt 1 ]]; then
    sv_warn "trimming moduli would leave none, skipping"
    rm -f "$tmp"; return 0
  fi
  sv_write_file ssh /etc/ssh/moduli 0644 <"$tmp"
  rm -f "$tmp"
  [[ $SV_CHANGED -eq 1 ]] && sv_ok "removed $weak DH moduli under 3072 bits"
  return 0
}

# On Ubuntu 22.10 and later sshd can be socket activated, in which case the
# Port directive is ignored and systemd decides what to listen on.
ssh_socket_port() {
  local port="$1"
  sv_sshd_socket_activated || return 0
  if [[ "$port" == "22" ]]; then
    [[ -f "$SV_SSH_SOCKET_DROPIN" ]] && sv_remove_file ssh "$SV_SSH_SOCKET_DROPIN"
    return 0
  fi
  sv_info "sshd is socket activated, setting the port on ssh.socket instead"
  sv_write_file ssh "$SV_SSH_SOCKET_DROPIN" 0644 <<EOF
$(sv_managed_header)
[Socket]
# An empty ListenStream clears the inherited value before the new one is added.
ListenStream=
ListenStream=$port
EOF
  if [[ $SV_CHANGED -eq 1 ]] && ! sv_dry; then
    systemctl daemon-reload
  fi
}

# Arm a timer that puts the old sshd config back unless someone confirms a
# working session first.
ssh_arm_rollback() {
  local timeout; timeout="$(sv_int ssh.rollback-timeout)"
  [[ "$timeout" -eq 0 ]] && return 0
  sv_dry && return 0
  if [[ $SV_HAS_SYSTEMD -eq 0 ]]; then
    sv_warn "no systemd, cannot arm the rollback timer. Keep this session open until you have tested a new one."
    return 0
  fi

  local prev_dropin="" prev_socket=""
  [[ -n "$SV_BACKUP_DIR" && -f "$SV_BACKUP_DIR/files/${SV_SSHD_DROPIN//\//__}" ]] \
    && prev_dropin="$SV_BACKUP_DIR/files/${SV_SSHD_DROPIN//\//__}"
  [[ -n "$SV_BACKUP_DIR" && -f "$SV_BACKUP_DIR/files/${SV_SSH_SOCKET_DROPIN//\//__}" ]] \
    && prev_socket="$SV_BACKUP_DIR/files/${SV_SSH_SOCKET_DROPIN//\//__}"

  local tmp; tmp="$(mktemp)"
  cat >"$tmp" <<EOF
#!/bin/sh
# Written by securevps.sh. Restores the sshd configuration that was in place
# before $SV_RUN_ID, then removes itself.
set -u
if [ -n "$prev_dropin" ] && [ -f "$prev_dropin" ]; then
  cp "$prev_dropin" "$SV_SSHD_DROPIN"
else
  rm -f "$SV_SSHD_DROPIN"
fi
if [ -n "$prev_socket" ] && [ -f "$prev_socket" ]; then
  cp "$prev_socket" "$SV_SSH_SOCKET_DROPIN"
else
  rm -f "$SV_SSH_SOCKET_DROPIN"
fi
systemctl daemon-reload 2>/dev/null || true
systemctl restart ssh.socket 2>/dev/null || true
systemctl restart $(sv_sshd_unit) 2>/dev/null || systemctl reload $(sv_sshd_unit) 2>/dev/null || true
logger -t securevps "sshd configuration rolled back, nobody confirmed the change"
rm -f "$SV_STATE_DIR/ssh-rollback-pending" "$SV_SSH_ROLLBACK"
EOF
  install -m 0700 "$tmp" "$SV_SSH_ROLLBACK"
  rm -f "$tmp"
  printf '%s\n' "$SV_RUN_ID" >"$SV_STATE_DIR/ssh-rollback-pending"

  systemctl stop securevps-ssh-rollback.timer >/dev/null 2>&1 || true
  systemd-run --quiet --unit=securevps-ssh-rollback \
    --on-active="$timeout" --timer-property=AccuracySec=1s \
    "$SV_SSH_ROLLBACK" >/dev/null 2>&1 || {
      sv_warn "could not arm the rollback timer"
      rm -f "$SV_STATE_DIR/ssh-rollback-pending"
      return 0
    }
  sv_ok "rollback armed, it fires in ${timeout}s unless you confirm"
  return 0
}

ssh_confirm_prompt() {
  local timeout; timeout="$(sv_int ssh.rollback-timeout)"
  [[ "$timeout" -eq 0 ]] && return 0
  sv_dry && return 0
  [[ -f "$SV_STATE_DIR/ssh-rollback-pending" ]] || return 0

  local port; port="$(sv_int ssh.port)"
  local addr; addr="$(hostname -I 2>/dev/null | awk '{print $1}')"
  sv_say ""
  sv_say "${C_BOLD}Do not close this session yet.${C_RESET}"
  sv_say "Open a second terminal and check you can still get in:"
  sv_say ""
  sv_say "    ssh -p $port $(sv_get user.name)@${addr:-<this server>}"
  sv_say ""
  sv_say "Then, in that new session, run:  ${C_BOLD}securevps.sh confirm${C_RESET}"
  sv_say "If nobody confirms within ${timeout}s the old sshd config comes back by itself."

  if [[ -t 0 ]] && ! sv_bool core.yes; then
    if sv_confirm "Confirm now from this session instead (only if you already tested a new one)?" n; then
      sv_cmd_confirm
    fi
  fi
}

ssh_apply() {
  sv_header "ssh"

  if [[ ! -f /etc/ssh/sshd_config ]]; then
    sv_warn "no /etc/ssh/sshd_config, is openssh-server installed?"
    return 1
  fi

  # sshd -t needs the privilege separation directory, which systemd-tmpfiles
  # normally creates at boot. On a fresh or minimal install it may not exist
  # yet, and its absence has nothing to do with the configuration.
  if [[ ! -d /run/sshd ]] && ! sv_dry; then
    if mkdir -p /run/sshd 2>/dev/null; then chmod 0755 /run/sshd 2>/dev/null || true; fi
  fi

  if ! ssh_login_path_exists; then
    sv_err "This configuration would leave no way to log in."
    sv_err "  password auth: $(sv_get ssh.password-auth), root login: $(sv_get ssh.permit-root)"
    sv_err "  AllowGroups: $(sv_get ssh.allow-groups), AllowUsers: $(ssh_allow_users)"
    sv_err "No account matching those rules has an SSH key in its authorized_keys."
    sv_err "Add a key first, or re-run with --core-force if you know better."
    return 1
  fi

  # Whatever sshd already thinks of its config, so a pre-existing problem is
  # not blamed on this run.
  local before_err=""
  sv_dry || before_err="$(sshd -t 2>&1 || true)"

  ssh_ensure_include
  ssh_hostkeys
  ssh_moduli

  local before_port="$SV_CURRENT_SSH_PORTS"
  sv_write_gen ssh "$SV_SSHD_DROPIN" 0600 ssh_render_config
  local config_changed=$SV_CHANGED

  if ! sv_dry; then
    local after_err; after_err="$(sshd -t 2>&1 || true)"
    if [[ -n "$after_err" && "$after_err" != "$before_err" ]]; then
      sv_err "sshd rejected the generated config, restoring the previous one:"
      printf '%s\n' "$after_err" | sed 's/^/    /' >&2
      local stored="$SV_BACKUP_DIR/files/${SV_SSHD_DROPIN//\//__}"
      if [[ -f "$stored" ]]; then install -m 0600 "$stored" "$SV_SSHD_DROPIN"
      else rm -f "$SV_SSHD_DROPIN"; fi
      return 1
    fi
    if [[ -n "$before_err" ]]; then
      sv_warn "sshd was already failing its own config check before this run:"
      printf '%s\n' "$before_err" | sed 's/^/    /' >&2
      sv_note "sshd reported a pre-existing configuration problem. Fix it before relying on the hardening: sshd -t"
    fi
  fi

  ssh_socket_port "$(sv_int ssh.port)"
  local socket_changed=$SV_CHANGED

  if [[ $config_changed -eq 0 && $socket_changed -eq 0 ]]; then
    sv_skip "sshd already configured as requested"
    return 0
  fi

  ssh_arm_rollback

  if sv_sshd_socket_activated; then
    sv_svc_restart ssh.socket || true
    sv_svc_restart "$(sv_sshd_unit)" || true
  else
    sv_svc_reload "$(sv_sshd_unit)" || sv_svc_restart "$(sv_sshd_unit)" || true
  fi

  sv_ok "sshd on port $(sv_int ssh.port), keys only, root login $(sv_get ssh.permit-root)"
  if [[ "$before_port" != "$(sv_int ssh.port)" ]]; then
    sv_note "SSH moved from port $before_port to $(sv_int ssh.port). Update your ~/.ssh/config."
  fi
  if ! sv_bool ssh.tcp-forwarding; then
    sv_note "TCP forwarding is off, so 'ssh -L' tunnels will not work. Turn it back on with --ssh-tcp-forwarding if you reach an admin UI that way."
  fi

  ssh_confirm_prompt
  return 0
}

ssh_scan() {
  if ! sv_has_cmd sshd; then
    sv_check skip ssh sshd "sshd not installed"
    return 0
  fi

  sv_expect ssh password-auth   "password authentication" "$(sv_sshd_get passwordauthentication)" no
  sv_expect ssh root-login      "PermitRootLogin" "$(sv_sshd_get permitrootlogin)" no prohibit-password
  sv_expect ssh pubkey          "public key authentication" "$(sv_sshd_get pubkeyauthentication)" yes
  sv_expect ssh empty-passwords "PermitEmptyPasswords" "$(sv_sshd_get permitemptypasswords)" no
  sv_expect ssh x11             "X11Forwarding" "$(sv_sshd_get x11forwarding)" no

  local v
  v="$(sv_sshd_get maxauthtries)"
  if [[ -n "$v" && "$v" -le 4 ]]; then sv_check pass ssh max-auth-tries "MaxAuthTries $v"
  else sv_check warn ssh max-auth-tries "MaxAuthTries ${v:-unknown}"; fi

  v="$(sv_sshd_get port)"
  if [[ "$v" == "22" ]]; then sv_check warn ssh port "sshd is on the default port 22"
  else sv_check pass ssh port "sshd is on port $v"; fi

  local weak
  weak="$(sv_sshd_get kexalgorithms | tr ',' '\n' | grep -cE 'sha1|group1-|group14-sha1' || true)"
  if [[ "${weak:-0}" -eq 0 ]]; then sv_check pass ssh kex "no SHA-1 key exchange offered"
  else sv_check fail ssh kex "$weak key exchange algorithms use SHA-1"; fi

  sv_verdict ssh hostkeys "no obsolete host keys" "a DSA host key is still present" \
    test ! -f /etc/ssh/ssh_host_dsa_key

  if [[ -f /etc/ssh/moduli ]]; then
    weak="$(awk '$1 !~ /^#/ && $5 < 3071' /etc/ssh/moduli 2>/dev/null | wc -l)"
    if [[ "${weak:-0}" -eq 0 ]]; then sv_check pass ssh moduli "all DH moduli are 3072 bits or more"
    else sv_check fail ssh moduli "$weak DH moduli under 3072 bits"; fi
  fi

  if [[ -f "$SV_STATE_DIR/ssh-rollback-pending" ]]; then
    sv_check warn ssh rollback "an sshd rollback is armed, run: securevps.sh confirm"
  fi
}

# ==========================================================================
# firewall - default-deny inbound with only the ports you asked for
# ==========================================================================
#
# Deny inbound, allow outbound, SSH rate-limited. 80 and 443 are not opened
# unless you ask, because plenty of servers are not web servers and an open
# port should be something somebody typed.
#
# Whatever sshd listens on now and whatever it is about to listen on are both
# kept open, so changing the SSH port in the same run cannot strand you.


firewall_backend() {
  local want; want="$(sv_get firewall.backend)"
  case "$want" in
    ufw|nftables) printf '%s' "$want"; return 0 ;;
  esac
  if sv_has_cmd ufw; then printf 'ufw'
  elif sv_has_cmd nft; then printf 'nftables'
  else printf 'ufw'; fi
}

# Ports that must stay reachable or the run ends in a locked door: whatever
# sshd listens on now, plus whatever it is about to listen on.
firewall_ssh_ports() {
  local ports
  ports="$SV_CURRENT_SSH_PORTS $(sv_int ssh.port)"
  # shellcheck disable=SC2086  # deliberate word splitting
  printf '%s' "$(printf '%s\n' $ports | grep -E '^[0-9]+$' | sort -un | tr '\n' ' ' | sed 's/ $//')"
}

# Parse "80,443,25/tcp" into "80/tcp 443/tcp 25/tcp".
firewall_parse_allow() {
  local spec="$1" item port proto out=""
  for item in ${spec//,/ }; do
    [[ -z "$item" ]] && continue
    port="${item%%/*}"
    proto="tcp"
    [[ "$item" == */* ]] && proto="${item##*/}"
    out="$out $port/$proto"
  done
  printf '%s' "${out# }"
}

firewall_apply_ufw() {
  sv_pkg_install ufw || { sv_warn "ufw is not available"; return 1; }

  local port
  if sv_dry; then
    sv_would "ufw default deny incoming / allow outgoing"
    for port in $(firewall_ssh_ports); do sv_would "ufw limit $port/tcp"; done
    for port in $(firewall_parse_allow "$(sv_get firewall.allow)"); do sv_would "ufw allow $port"; done
    sv_would "ufw --force enable"
    return 0
  fi

  # IPv6 is a property of the config file, not a rule.
  sv_set_kv firewall /etc/default/ufw IPV6 "$(sv_onoff firewall.ipv6)" "="

  ufw --force default deny incoming >/dev/null
  ufw --force default allow outgoing >/dev/null
  ufw --force default deny routed >/dev/null 2>&1 || true

  for port in $(firewall_ssh_ports); do
    if sv_bool firewall.ssh-limit; then
      ufw limit "$port/tcp" comment 'securevps ssh' >/dev/null
    else
      ufw allow "$port/tcp" comment 'securevps ssh' >/dev/null
    fi
  done

  for port in $(firewall_parse_allow "$(sv_get firewall.allow)"); do
    ufw allow "$port" comment 'securevps' >/dev/null
  done

  local rule cidr target from_spec
  from_spec="$(sv_get firewall.allow-from)"
  for rule in ${from_spec//,/ }; do
    [[ -z "$rule" ]] && continue
    cidr="${rule%%:*}"; target="${rule##*:}"
    ufw allow from "$cidr" to any port "${target%%/*}" \
      proto "$( [[ "$target" == */* ]] && printf '%s' "${target##*/}" || printf 'tcp' )" \
      comment 'securevps scoped' >/dev/null
  done

  ufw logging "$(sv_get firewall.log-level)" >/dev/null 2>&1 || true

  if sv_bool firewall.enable; then
    ufw --force enable >/dev/null
    sv_svc_enable ufw.service || true
  fi
  SV_MODULE_CHANGES=$((SV_MODULE_CHANGES + 1))
  return 0
}

firewall_apply_nftables() {
  sv_pkg_install nftables || { sv_warn "nftables is not available"; return 1; }

  local ssh_ports allow_tcp allow_udp="" p
  ssh_ports="$(firewall_ssh_ports | tr ' ' ',')"
  allow_tcp="$ssh_ports"
  for p in $(firewall_parse_allow "$(sv_get firewall.allow)"); do
    if [[ "$p" == */udp ]]; then allow_udp="${allow_udp:+$allow_udp,}${p%%/*}"
    else allow_tcp="$allow_tcp,${p%%/*}"; fi
  done

  local icmp_rule="icmp type echo-request accept"
  sv_bool firewall.block-ping && icmp_rule="icmp type echo-request drop"
  local log_rule=""
  [[ "$(sv_get firewall.log-level)" != "off" ]] && log_rule='log prefix "securevps-drop " limit rate 5/minute'

  sv_write_file firewall /etc/nftables.conf 0644 <<EOF
#!/usr/sbin/nft -f
$(sv_managed_header)

flush ruleset

table inet filter {
  chain input {
    type filter hook input priority filter; policy drop;

    ct state established,related accept
    ct state invalid drop
    iif lo accept

    $icmp_rule
    icmpv6 type { echo-request, nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept

    tcp dport { $allow_tcp } ct state new accept
$( [[ -n "$allow_udp" ]] && printf '    udp dport { %s } ct state new accept\n' "$allow_udp" )
$( [[ -n "$log_rule" ]] && printf '    %s\n' "$log_rule" )
  }

  chain forward {
    type filter hook forward priority filter; policy $( [[ $SV_HAS_DOCKER -eq 1 ]] && printf 'accept' || printf 'drop' );
  }

  chain output {
    type filter hook output priority filter; policy accept;
  }
}
EOF

  if [[ $SV_CHANGED -eq 1 ]] && ! sv_dry; then
    if ! sv_validate "nftables ruleset" nft -c -f /etc/nftables.conf; then
      sv_err "the generated nftables ruleset is invalid, not loading it"
      return 1
    fi
    sv_bool firewall.enable && sv_svc_enable nftables.service
  fi
  return 0
}

firewall_apply() {
  sv_header "firewall"
  local backend; backend="$(firewall_backend)"

  if [[ $SV_IS_CONTAINER -eq 1 ]]; then
    sv_skip "running in a container, the host owns the firewall"
    return 0
  fi

  sv_info "backend: $backend, ssh ports kept open: $(firewall_ssh_ports)"

  case "$backend" in
    ufw) firewall_apply_ufw || return 1 ;;
    nftables) firewall_apply_nftables || return 1 ;;
  esac

  sv_ok "inbound denied by default, open: $(firewall_ssh_ports) $(firewall_parse_allow "$(sv_get firewall.allow)")"
  if [[ $SV_HAS_DOCKER -eq 1 ]] && ! sv_bool docker.firewall-fix; then
    sv_note "Docker is installed and the firewall fix is off. Published container ports bypass these rules entirely."
  fi
  return 0
}

firewall_scan() {
  local backend; backend="$(firewall_backend)"
  if [[ $SV_IS_CONTAINER -eq 1 ]]; then
    sv_check skip firewall active "in a container, the host owns the firewall"
    return 0
  fi

  case "$backend" in
    ufw)
      if ! sv_has_cmd ufw; then sv_check fail firewall installed "ufw not installed"; return 0; fi
      sv_check pass firewall installed "ufw installed"
      sv_verdict firewall active "ufw is active" "ufw is installed but not active" \
        sv_grep_cmd 'Status: active' ufw status
      sv_verdict firewall default-deny \
        "default incoming policy is deny" "default incoming policy is not deny" \
        sv_grep_cmd 'Default: deny (incoming)' ufw status verbose
      ;;
    nftables)
      if ! sv_has_cmd nft; then sv_check fail firewall installed "nft not installed"; return 0; fi
      sv_check pass firewall installed "nftables installed"
      sv_verdict firewall default-deny \
        "input policy is drop" "input chain is not default-drop" \
        sv_grep_cmd 'policy drop' nft list chain inet filter input
      ;;
  esac

  # What is actually listening on a public address, which is the number that
  # matters more than the rule count.
  if sv_has_cmd ss; then
    local public
    public="$(ss -H -ltn 2>/dev/null | awk '{print $4}' \
      | grep -vE '^(127\.|\[::1\]|\[?::1\]?)' | grep -E '^(0\.0\.0\.0|\[::\]|\*)' \
      | sed 's/.*://' | sort -un | tr '\n' ' ' || true)"
    if [[ -n "${public// /}" ]]; then
      sv_check warn firewall listening "listening on every interface: $public"
    else
      sv_check pass firewall listening "nothing listening on a wildcard address"
    fi
  fi
}

# ==========================================================================
# docker - stop published container ports bypassing the firewall
# ==========================================================================
#
# Docker writes its own iptables rules and they are evaluated before ufw's.
# 'docker run -p 5432:5432' answers the internet with 'ufw deny 5432' in
# place and ufw status showing the rule. A great many people believe their
# database is firewalled when it is not.
#
# DOCKER-USER is consulted before Docker's own accept rules and Docker never
# rewrites it, so a default DROP there actually holds. Restarting the daemon
# flushes the chain, hence the unit that puts the rules back.


readonly SV_DOCKER_SCRIPT="/usr/local/sbin/securevps-docker-firewall"
readonly SV_DOCKER_UNIT="/etc/systemd/system/securevps-docker-firewall.service"

docker_allow_cidrs_v4() {
  local out="127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
  local c
  for c in $(printf '%s' "$(sv_get docker.allow-from)" | tr ',' ' '); do
    [[ "$c" == *:* ]] && continue
    out="$out $c"
  done
  printf '%s' "$out"
}

docker_allow_cidrs_v6() {
  local out="::1/128 fc00::/7"
  local c
  for c in $(printf '%s' "$(sv_get docker.allow-from)" | tr ',' ' '); do
    [[ "$c" == *:* ]] || continue
    out="$out $c"
  done
  printf '%s' "$out"
}

# A standalone script, so the systemd unit does not depend on where
# securevps.sh happens to be sitting when it is run.
docker_render_script() {
  local published; published="$(firewall_parse_allow "$(sv_get docker.allow-published)")"

  cat <<'EOF'
#!/bin/sh
# Managed by securevps.sh. Regenerated on every run of the docker step.
#
# Docker inserts its own rules ahead of ufw's, so "ufw deny 5432" does not
# stop "docker run -p 5432:5432" from answering the internet. DOCKER-USER is
# consulted before Docker's own accept rules and Docker never rewrites it,
# which makes it the one place a default drop actually holds.
#
# Docker flushes this chain when the daemon restarts, so the systemd unit
# runs this script again afterwards.
set -u
EOF

  local family ipt cidrs c p
  for family in 4 6; do
    if [[ "$family" == 4 ]]; then
      ipt=iptables; cidrs="$(docker_allow_cidrs_v4)"
    else
      ipt=ip6tables; cidrs="$(docker_allow_cidrs_v6)"
    fi
    printf '\nv%s() {\n' "$family"
    printf '  %s -N DOCKER-USER 2>/dev/null || true\n' "$ipt"
    printf '  %s -F DOCKER-USER\n' "$ipt"
    printf '  %s -A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN\n' "$ipt"
    printf '  %s -A DOCKER-USER -i lo -j RETURN\n' "$ipt"
    for c in $cidrs; do
      printf '  %s -A DOCKER-USER -s %s -j RETURN\n' "$ipt" "$c"
    done
    for p in $published; do
      printf '  %s -A DOCKER-USER -p %s --dport %s -j RETURN\n' "$ipt" "${p##*/}" "${p%%/*}"
    done
    printf '  %s -A DOCKER-USER -j DROP\n}\n' "$ipt"
  done

  cat <<'EOF'

command -v iptables >/dev/null 2>&1 && v4
command -v ip6tables >/dev/null 2>&1 && v6
exit 0
EOF
}

docker_apply() {
  # Reapply the rules from an earlier run and stop. The systemd unit runs the
  # standalone script directly; this is for doing the same by hand.
  if sv_bool docker.only-rules; then
    [[ -x "$SV_DOCKER_SCRIPT" ]] || return 1
    "$SV_DOCKER_SCRIPT"
    return 0
  fi

  sv_header "docker"

  if [[ $SV_HAS_DOCKER -eq 0 ]]; then
    sv_skip "Docker is not installed"
    return 0
  fi

  if sv_bool docker.daemon-config; then
    local icc live_restore userland
    icc="$(sv_bool docker.icc && printf true || printf false)"
    live_restore="$(sv_bool docker.live-restore && printf true || printf false)"
    userland="$(sv_bool docker.userland-proxy && printf true || printf false)"

    # Merge rather than overwrite: an existing daemon.json usually carries
    # settings this script knows nothing about.
    local merged
    if [[ -f /etc/docker/daemon.json ]] && sv_has_cmd python3; then
      merged="$(SV_ICC="$icc" SV_LR="$live_restore" SV_UP="$userland" \
        SV_NNP="$(sv_bool docker.no-new-privileges && printf true || printf false)" \
        SV_LMS="$(sv_get docker.log-max-size)" SV_LMF="$(sv_int docker.log-max-file)" \
        python3 - <<'PY' 2>/dev/null || true
import json, os, sys
try:
    cfg = json.load(open("/etc/docker/daemon.json"))
except Exception:
    cfg = {}
b = lambda k: os.environ[k] == "true"
cfg["icc"] = b("SV_ICC")
cfg["live-restore"] = b("SV_LR")
cfg["userland-proxy"] = b("SV_UP")
cfg["no-new-privileges"] = b("SV_NNP")
cfg["log-driver"] = cfg.get("log-driver", "json-file")
opts = cfg.get("log-opts") or {}
opts["max-size"] = os.environ["SV_LMS"]
opts["max-file"] = os.environ["SV_LMF"]
cfg["log-opts"] = opts
json.dump(cfg, sys.stdout, indent=2, sort_keys=True)
sys.stdout.write("\n")
PY
)"
    fi
    if [[ -z "${merged:-}" ]]; then
      merged="$(cat <<EOF
{
  "icc": $icc,
  "live-restore": $live_restore,
  "log-driver": "json-file",
  "log-opts": {
    "max-file": "$(sv_int docker.log-max-file)",
    "max-size": "$(sv_get docker.log-max-size)"
  },
  "no-new-privileges": $(sv_bool docker.no-new-privileges && printf true || printf false),
  "userland-proxy": $userland
}
EOF
)"
    fi

    sv_write_file docker /etc/docker/daemon.json 0644 <<<"$merged"
    if [[ $SV_CHANGED -eq 1 ]]; then
      sv_ok "daemon.json updated"
      if ! sv_dry; then
        if sv_validate "docker daemon.json" python3 -c \
             'import json,sys; json.load(open("/etc/docker/daemon.json"))'; then
          sv_svc_restart docker.service || sv_warn "restart docker to pick up daemon.json"
        else
          sv_err "generated daemon.json is not valid JSON, not restarting docker"
          return 1
        fi
      fi
    else
      sv_skip "daemon.json already correct"
    fi
    sv_bool docker.icc || sv_note "Container-to-container traffic on the default bridge is off. Containers that talked to each other without a user-defined network will stop working."
  fi

  if sv_bool docker.firewall-fix; then
    sv_write_gen docker "$SV_DOCKER_SCRIPT" 0755 docker_render_script

    sv_write_file docker "$SV_DOCKER_UNIT" 0644 <<EOF
$(sv_managed_header)
[Unit]
Description=securevps.sh DOCKER-USER firewall rules
After=docker.service network-online.target
Requires=docker.service
PartOf=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$SV_DOCKER_SCRIPT

[Install]
WantedBy=multi-user.target
EOF

    if sv_dry; then
      sv_would "install DOCKER-USER default-drop rules and a unit that reapplies them"
    else
      if ! sv_has_cmd iptables; then
        sv_warn "iptables is missing, cannot fix the Docker firewall bypass"
        return 1
      fi
      "$SV_DOCKER_SCRIPT" || { sv_err "the DOCKER-USER rules did not apply"; return 1; }
      systemctl daemon-reload >/dev/null 2>&1 || true
      sv_svc_enable securevps-docker-firewall.service || true
      SV_MODULE_CHANGES=$((SV_MODULE_CHANGES + 1))
      sv_ok "published container ports are now filtered by DOCKER-USER"
    fi
    local pub; pub="$(sv_get docker.allow-published)"
    sv_note "Container ports are reachable only from private networks${pub:+, plus $pub publicly}. Open more with --docker-allow-published 80,443."
  fi

  docker_report_exposure
  return 0
}

# Things this module cannot fix on its own but you should know about.
docker_report_exposure() {
  sv_has_cmd docker || return 0
  docker info >/dev/null 2>&1 || { sv_debug "docker daemon not responding"; return 0; }

  local wide
  wide="$(docker ps --format '{{.Names}}\t{{.Ports}}' 2>/dev/null \
    | grep -E '0\.0\.0\.0:|\[::\]:' | awk '{print $1}' | tr '\n' ' ' || true)"
  if [[ -n "${wide// /}" ]]; then
    sv_warn "containers publishing to every interface: ${wide}"
    sv_note "Those containers bind 0.0.0.0. Bind them to 127.0.0.1 in your compose file unless they are meant to be public."
  fi

  local sockmounts
  sockmounts="$(docker ps -q 2>/dev/null | xargs -r docker inspect \
    --format '{{.Name}} {{range .Mounts}}{{.Source}} {{end}}' 2>/dev/null \
    | grep -F '/var/run/docker.sock' | awk '{print $1}' | tr '\n' ' ' || true)"
  if [[ -n "${sockmounts// /}" ]]; then
    sv_warn "containers with the Docker socket mounted: ${sockmounts}"
    sv_note "A container holding /var/run/docker.sock is root on the host. Treat those containers as trusted infrastructure."
  fi

  local dockergroup
  dockergroup="$(getent group docker 2>/dev/null | cut -d: -f4)"
  if [[ -n "${dockergroup:-}" ]]; then
    sv_note "Members of the docker group are root-equivalent: ${dockergroup}"
  fi
}

docker_scan() {
  if [[ $SV_HAS_DOCKER -eq 0 ]]; then
    sv_check skip docker installed "Docker is not installed"
    return 0
  fi

  sv_verdict docker firewall-bypass \
    "DOCKER-USER ends in DROP, published ports are filtered" \
    "DOCKER-USER has no default drop, published container ports bypass the firewall" \
    sv_grep_cmd '-j DROP' iptables -S DOCKER-USER

  sv_verdict docker rules-persist \
    "the DOCKER-USER rules are reapplied after a docker restart" \
    "nothing reapplies the DOCKER-USER rules after a docker restart" \
    sv_unit_enabled securevps-docker-firewall.service

  if [[ -f /etc/docker/daemon.json ]]; then
    local j; j="$(cat /etc/docker/daemon.json)"
    if grep -q '"no-new-privileges": *true' <<<"$j"; then
      sv_check pass docker no-new-privileges "no-new-privileges is on"
    else
      sv_check fail docker no-new-privileges "no-new-privileges is not set"
    fi
    if grep -q '"live-restore": *true' <<<"$j"; then
      sv_check pass docker live-restore "live-restore is on"
    else
      sv_check warn docker live-restore "live-restore is off, containers stop when the daemon restarts"
    fi
    if grep -q '"max-size"' <<<"$j"; then
      sv_check pass docker log-rotation "container logs rotate"
    else
      sv_check fail docker log-rotation "container logs are not rotated and will fill the disk"
    fi
  else
    sv_check fail docker daemon-config "no /etc/docker/daemon.json"
  fi

  local wide
  wide="$(docker ps --format '{{.Names}}\t{{.Ports}}' 2>/dev/null \
    | grep -cE '0\.0\.0\.0:|\[::\]:' || true)"
  if [[ "${wide:-0}" -gt 0 ]]; then
    sv_check warn docker wildcard-publish "$wide container(s) publish to every interface"
  else
    sv_check pass docker wildcard-publish "no container publishes to a wildcard address"
  fi

  local members; members="$(getent group docker 2>/dev/null | cut -d: -f4)"
  if [[ -n "${members:-}" ]]; then
    sv_check warn docker group "docker group members are root-equivalent: $members"
  else
    sv_check pass docker group "the docker group is empty"
  fi
}

# ==========================================================================
# bruteforce - ban addresses that keep failing to log in
# ==========================================================================
#
# With key-only auth already in place this mostly saves log volume rather
# than stopping a real attack, but log volume is worth saving.
#
# The address you are connected from goes on the never-ban list. Fail2ban
# banning the administrator mid-setup is a rite of passage nobody needs.


bruteforce_ignore_list() {
  local list="127.0.0.1/8 ::1"
  local extra; extra="$(sv_get bruteforce.ignore-ip)"
  [[ -n "$extra" ]] && list="$list ${extra//,/ }"
  if sv_bool bruteforce.auto-ignore-ip && [[ -n "$SV_CLIENT_IP" ]]; then
    list="$list $SV_CLIENT_IP"
  fi
  printf '%s' "$list"
}

bruteforce_apply_fail2ban() {
  sv_pkg_install fail2ban || { sv_warn "fail2ban is not available"; return 1; }

  local banaction="iptables-multiport"
  [[ "$(firewall_backend)" == "ufw" ]] && sv_has_cmd ufw && banaction="ufw"
  [[ "$(firewall_backend)" == "nftables" ]] && banaction="nftables-multiport"

  local mode="normal"
  sv_bool bruteforce.aggressive && mode="aggressive"

  local ports; ports="$(firewall_ssh_ports | tr ' ' ',')"

  sv_write_file bruteforce /etc/fail2ban/jail.d/99-securevps.local 0644 <<EOF
$(sv_managed_header)

[DEFAULT]
banaction = $banaction
banaction_allports = $banaction
backend = systemd
ignoreip = $(bruteforce_ignore_list)
findtime = $(sv_get bruteforce.findtime)
bantime = $(sv_get bruteforce.bantime)
maxretry = $(sv_int bruteforce.maxretry)

[sshd]
enabled = true
port = $ports
mode = $mode
EOF

  if sv_bool bruteforce.recidive; then
    # The recidive jail watches fail2ban's own log, so it needs a file backend
    # and a log to read regardless of what the other jails use.
    sv_write_file bruteforce /etc/fail2ban/jail.d/99-securevps-recidive.local 0644 <<EOF
$(sv_managed_header)

[recidive]
enabled = true
backend = auto
logpath = /var/log/fail2ban.log
banaction = $banaction
findtime = 1d
bantime = 1w
maxretry = 3
EOF
    # systemd backend does not write that log by default.
    sv_write_file bruteforce /etc/fail2ban/fail2ban.d/99-securevps-log.conf 0644 <<EOF
$(sv_managed_header)
[Definition]
logtarget = /var/log/fail2ban.log
EOF
  else
    [[ -f /etc/fail2ban/jail.d/99-securevps-recidive.local ]] \
      && sv_remove_file bruteforce /etc/fail2ban/jail.d/99-securevps-recidive.local
  fi

  if ! sv_dry; then
    if ! sv_validate "fail2ban config" fail2ban-client -t; then
      sv_err "fail2ban rejected the generated config"
      return 1
    fi
  fi

  sv_svc_enable fail2ban.service || return 1
  sv_svc_restart fail2ban.service || true
  sv_ok "fail2ban watching ssh on $ports, $(sv_int bruteforce.maxretry) tries per $(sv_get bruteforce.findtime), banned for $(sv_get bruteforce.bantime)"
  [[ -n "$SV_CLIENT_IP" ]] && sv_bool bruteforce.auto-ignore-ip \
    && sv_ok "your address $SV_CLIENT_IP is on the never-ban list"
  return 0
}

bruteforce_apply_crowdsec() {
  if ! sv_pkg_installed crowdsec; then
    sv_warn "CrowdSec is not in the distribution repositories."
    sv_note "Install CrowdSec first (https://doc.crowdsec.net/docs/getting_started/install_crowdsec), then run: securevps.sh bruteforce --engine crowdsec"
    return 1
  fi
  sv_pkg_install crowdsec-firewall-bouncer-iptables || true
  if ! sv_dry; then
    cscli collections install crowdsecurity/sshd crowdsecurity/linux >/dev/null 2>&1 || true
    sv_svc_enable crowdsec.service || true
    sv_svc_enable crowdsec-firewall-bouncer.service || true
  fi
  sv_ok "CrowdSec running with the sshd and linux collections"
  return 0
}

bruteforce_apply() {
  sv_header "bruteforce"
  case "$(sv_get bruteforce.engine)" in
    none) sv_skip "no brute force protection requested"; return 0 ;;
    fail2ban) bruteforce_apply_fail2ban ;;
    crowdsec) bruteforce_apply_crowdsec ;;
    *) sv_err "unknown engine: $(sv_get bruteforce.engine)"; return 1 ;;
  esac
}

bruteforce_scan() {
  local engine; engine="$(sv_get bruteforce.engine)"
  if [[ "$engine" == none ]]; then
    sv_check skip bruteforce engine "brute force protection disabled by configuration"
    return 0
  fi

  if [[ "$engine" == crowdsec ]]; then
    sv_verdict bruteforce running "CrowdSec is running" "CrowdSec is not running" \
      sv_unit_active crowdsec.service
    return 0
  fi

  if ! sv_pkg_installed fail2ban; then
    sv_check fail bruteforce installed "fail2ban is not installed"
    return 0
  fi
  sv_check pass bruteforce installed "fail2ban is installed"

  if sv_unit_active fail2ban.service; then
    sv_check pass bruteforce running "fail2ban is running"
  else
    sv_check fail bruteforce running "fail2ban is installed but not running"
    return 0
  fi

  if fail2ban-client status 2>/dev/null | grep -q 'sshd'; then
    sv_check pass bruteforce sshd-jail "the sshd jail is active"
    local banned
    banned="$(fail2ban-client status sshd 2>/dev/null | awk -F: '/Currently banned/{gsub(/ /,"",$2); print $2}')"
    [[ -n "${banned:-}" ]] && sv_check pass bruteforce banned "$banned address(es) currently banned"
  else
    sv_check fail bruteforce sshd-jail "no sshd jail is active"
  fi

  local jail_ports
  jail_ports="$(awk -F= '/^port/{gsub(/ /,"",$2); print $2}' /etc/fail2ban/jail.d/99-securevps.local 2>/dev/null || true)"
  local ssh_port; ssh_port="$(sv_sshd_get port)"
  if [[ -n "$ssh_port" && -n "$jail_ports" ]] && ! grep -qw "$ssh_port" <<<"${jail_ports//,/ }"; then
    sv_check fail bruteforce jail-port "the sshd jail watches $jail_ports but sshd listens on $ssh_port"
  elif [[ -n "$jail_ports" ]]; then
    sv_check pass bruteforce jail-port "the sshd jail covers the port sshd listens on"
  fi
}

# ==========================================================================
# sysctl - kernel and network stack hardening
# ==========================================================================
#
# Reverse-path filtering, no source routing, no ICMP redirects, SYN cookies,
# martian logging, and kernel restrictions that turn a local information leak
# into a dead end.
#
# ip_forward and unprivileged user namespaces are left alone when Docker is
# installed, because turning either off breaks container networking.


sysctl_ip_forward() {
  case "$(sv_get sysctl.ip-forward)" in
    on) printf 1 ;;
    off) printf 0 ;;
    *) [[ $SV_HAS_DOCKER -eq 1 ]] && printf 1 || printf 0 ;;
  esac
}

sysctl_render() {
  sv_managed_header
  local fwd; fwd="$(sysctl_ip_forward)"

  if sv_bool sysctl.network; then
    cat <<EOF

# --- network ---
# Drop packets whose source address could not have come from that interface.
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
# Source routing lets the sender pick the return path. Nothing legitimate uses it.
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
# ICMP redirects can rewrite the routing table from the network.
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
# Survive a SYN flood without a connection table full of half-open sockets.
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_synack_retries = 2
# Ignore broadcast pings and malformed error replies.
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
# Log packets with impossible addresses; they mean something is spoofing.
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
# Protect against the TIME-WAIT assassination described in RFC 1337.
net.ipv4.tcp_rfc1337 = 1
# Refuse router advertisements; this host is not a client on someone's LAN.
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv4.ip_forward = $fwd
EOF
    sv_bool sysctl.ipv6 || cat <<'EOF'
# IPv6 fully disabled by request.
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
  fi

  if sv_bool sysctl.kernel; then
    cat <<EOF

# --- kernel ---
# Hide kernel addresses and the ring buffer from unprivileged users; both are
# reconnaissance for a local privilege escalation.
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
# Nothing should be loading a replacement kernel at runtime.
kernel.kexec_load_disabled = 1
# The magic SysRq key is a console-local root shell.
kernel.sysrq = 0
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.perf_event_paranoid = 3
# Restrict which processes may be attached to with ptrace.
kernel.yama.ptrace_scope = $(sv_int sysctl.ptrace-scope)
kernel.randomize_va_space = 2
# Do not put PIDs, hostnames or paths in core dump filenames.
kernel.core_uses_pid = 1
EOF
    sv_bool sysctl.userns || printf '%s\n' "kernel.unprivileged_userns_clone = 0"
  fi

  if sv_bool sysctl.filesystem; then
    cat <<'EOF'

# --- filesystem ---
# Stop the classic symlink and hardlink races in world-writable directories.
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
# A setuid process dumping core writes privileged memory to disk.
fs.suid_dumpable = 0
EOF
  fi
}

sysctl_apply() {
  sv_header "sysctl"

  if [[ $SV_IS_CONTAINER -eq 1 ]]; then
    sv_skip "running in a container, the host kernel is not ours to tune"
    return 0
  fi

  sv_write_gen sysctl /etc/sysctl.d/99-securevps.conf 0644 sysctl_render

  if [[ $SV_CHANGED -eq 1 ]] && ! sv_dry; then
    # Individual keys can be missing on a given kernel, which is not fatal.
    local failed=0 line key
    while read -r line; do
      [[ "$line" =~ ^[[:space:]]*# || -z "${line// /}" ]] && continue
      key="${line%%=*}"; key="${key// /}"
      sysctl -qw "${line// /}" >/dev/null 2>&1 || { sv_debug "kernel rejected $key"; failed=$((failed + 1)); }
    done < /etc/sysctl.d/99-securevps.conf
    [[ $failed -gt 0 ]] && sv_debug "$failed sysctl keys not supported by this kernel"
    sv_ok "kernel parameters applied"
  elif [[ $SV_CHANGED -eq 0 ]]; then
    sv_skip "kernel parameters already set"
  fi

  [[ "$(sysctl_ip_forward)" == "1" ]] && sv_debug "ip_forward left on, this host routes"
  sv_bool sysctl.ipv6 || sv_note "IPv6 is disabled. If your provider hands out an IPv6 address, it will stop responding."
  return 0
}

sysctl_scan() {
  if [[ $SV_IS_CONTAINER -eq 1 ]]; then
    sv_check skip sysctl container "in a container, the host kernel is not ours"
    return 0
  fi
  local -a keys=(
    net.ipv4.conf.all.rp_filter:1
    net.ipv4.conf.all.accept_source_route:0
    net.ipv4.conf.all.accept_redirects:0
    net.ipv4.tcp_syncookies:1
    net.ipv4.icmp_echo_ignore_broadcasts:1
    kernel.kptr_restrict:2
    kernel.dmesg_restrict:1
    kernel.sysrq:0
    fs.protected_hardlinks:1
    fs.protected_symlinks:1
    fs.suid_dumpable:0
  )
  local entry key want got bad=0 total=0
  for entry in "${keys[@]}"; do
    key="${entry%%:*}"; want="${entry##*:}"
    got="$(sysctl -n "$key" 2>/dev/null || true)"
    [[ -z "$got" ]] && continue
    total=$((total + 1))
    [[ "$got" == "$want" ]] || { bad=$((bad + 1)); sv_debug "$key is $got, wanted $want"; }
  done
  if [[ $bad -eq 0 ]]; then
    sv_check pass sysctl parameters "all $total checked kernel parameters are hardened"
  else
    sv_check fail sysctl parameters "$bad of $total kernel parameters are not hardened (run with --verbose to see which)"
  fi

  if [[ -f /etc/sysctl.d/99-securevps.conf ]]; then
    sv_check pass sysctl persisted "settings persist across reboot"
  else
    sv_check fail sysctl persisted "no /etc/sysctl.d/99-securevps.conf, settings will not survive a reboot"
  fi
}

# ==========================================================================
# kmodules - blacklist filesystems and protocols a VPS never uses
# ==========================================================================
#
# Drivers for filesystems and network protocols no server touches are still
# attack surface. squashfs is deliberately absent from the list, because
# snap packages will not mount without it.


kmodules_list() {
  local out=""
  sv_bool kmodules.filesystems && out="$out cramfs freevxfs jffs2 hfs hfsplus udf"
  sv_bool kmodules.protocols && out="$out dccp sctp rds tipc"
  local extra; extra="$(sv_get kmodules.extra)"
  [[ -n "$extra" ]] && out="$out ${extra//,/ }"
  printf '%s' "${out# }"
}

kmodules_render() {
  sv_managed_header
  printf '\n# squashfs is deliberately absent: snap packages will not mount without it.\n'
  local m
  for m in $(kmodules_list); do
    printf 'install %s /bin/false\n' "$m"
    printf 'blacklist %s\n' "$m"
  done
}

kmodules_apply() {
  sv_header "kmodules"
  if [[ $SV_IS_CONTAINER -eq 1 ]]; then
    sv_skip "running in a container, module loading belongs to the host"
    return 0
  fi

  local mods; mods="$(kmodules_list)"
  if [[ -z "$mods" ]]; then
    sv_skip "nothing to blacklist"
    return 0
  fi

  sv_write_gen kmodules /etc/modprobe.d/99-securevps.conf 0644 kmodules_render

  if [[ $SV_CHANGED -eq 1 ]]; then sv_ok "blacklisted: $mods"
  else sv_skip "blacklist already in place"; fi

  # Unload anything already loaded that we just blacklisted, if it is idle.
  if ! sv_dry; then
    local m
    for m in $mods; do
      lsmod 2>/dev/null | awk '{print $1}' | grep -qx "${m//-/_}" || continue
      if modprobe -r "$m" >/dev/null 2>&1; then
        sv_ok "unloaded $m"
      else
        sv_debug "$m is loaded and in use, it will stay until reboot"
      fi
    done
  fi
  return 0
}

kmodules_scan() {
  if [[ $SV_IS_CONTAINER -eq 1 ]]; then
    sv_check skip kmodules container "in a container, module loading belongs to the host"
    return 0
  fi
  local mods; mods="$(kmodules_list)"
  [[ -z "$mods" ]] && { sv_check skip kmodules blacklist "no modules configured for blacklisting"; return 0; }

  local m absent=0 loaded=""
  for m in $mods; do
    grep -rqs "^install $m /bin/false" /etc/modprobe.d/ || absent=$((absent + 1))
    lsmod 2>/dev/null | awk '{print $1}' | grep -qx "${m//-/_}" && loaded="$loaded $m"
  done
  if [[ $absent -eq 0 ]]; then
    sv_check pass kmodules blacklist "all $(wc -w <<<"$mods") modules are blacklisted"
  else
    sv_check fail kmodules blacklist "$absent modules are not blacklisted"
  fi
  if [[ -n "${loaded// /}" ]]; then
    sv_check warn kmodules loaded "still loaded until reboot:$loaded"
  else
    sv_check pass kmodules loaded "no blacklisted module is loaded"
  fi
}

# ==========================================================================
# mounts - nodev, nosuid and noexec on the writable scratch directories
# ==========================================================================
#
# /dev/shm is the one that is pure win: nothing legitimate executes or makes
# device nodes there, and it is a favourite staging area for exploits.
#
# /tmp and /var/tmp are opt-in. Package installers, language toolchains and
# container image builds all extract to them and run what they extracted.


mounts_unit() {
  local where="$1" opts="$2" name
  name="$(systemd-escape -p --suffix=mount "$where" 2>/dev/null)" || return 1
  sv_write_file mounts "/etc/systemd/system/$name" 0644 <<EOF
$(sv_managed_header)
[Unit]
Description=securevps.sh hardened $where
DefaultDependencies=no
Conflicts=umount.target
Before=local-fs.target umount.target

[Mount]
What=tmpfs
Where=$where
Type=tmpfs
Options=$opts

[Install]
WantedBy=local-fs.target
EOF
  printf '%s' "$name"
}

mounts_apply() {
  sv_header "mounts"
  if [[ $SV_IS_CONTAINER -eq 1 ]]; then
    sv_skip "running in a container, mounts belong to the host"
    return 0
  fi
  if [[ $SV_HAS_SYSTEMD -eq 0 ]]; then
    sv_warn "mount hardening here needs systemd"
    return 1
  fi

  local changed=0 unit

  if sv_bool mounts.dev-shm; then
    unit="$(mounts_unit /dev/shm "mode=1777,strictatime,nosuid,nodev,noexec,size=50%")" || true
    [[ $SV_CHANGED -eq 1 ]] && changed=1
  fi

  if sv_bool mounts.tmp; then
    local tmp_opts="mode=1777,strictatime,nosuid,nodev,size=25%"
    sv_bool mounts.noexec-tmp && tmp_opts="$tmp_opts,noexec"
    unit="$(mounts_unit /tmp "$tmp_opts")" || true
    [[ $SV_CHANGED -eq 1 ]] && changed=1
    sv_bool mounts.noexec-tmp && sv_note "/tmp is noexec. Some package postinst scripts, Docker builds and language installers extract to /tmp and run from there; they will fail."
  fi

  if sv_bool mounts.var-tmp; then
    # /var/tmp is meant to survive a reboot, so it gets a bind mount of itself
    # with the flags added rather than being replaced by a tmpfs.
    sv_write_file mounts /etc/systemd/system/var-tmp.mount 0644 <<EOF
$(sv_managed_header)
[Unit]
Description=securevps.sh hardened /var/tmp
DefaultDependencies=no
Conflicts=umount.target
Before=local-fs.target umount.target

[Mount]
What=/var/tmp
Where=/var/tmp
Type=none
Options=bind,nosuid,nodev,noexec

[Install]
WantedBy=local-fs.target
EOF
    [[ $SV_CHANGED -eq 1 ]] && changed=1
  fi

  if [[ $changed -eq 1 ]] && ! sv_dry; then
    systemctl daemon-reload
    local u
    for u in tmp.mount dev-shm.mount var-tmp.mount; do
      sv_unit_exists "$u" || continue
      systemctl enable "$u" >/dev/null 2>&1 || true
    done
    sv_ok "mount options written, they take effect on the next reboot"
    sv_note "Mount hardening applies at boot. Reboot when convenient, then run: securevps.sh scan"
  else
    sv_skip "mount options already as requested"
  fi
  return 0
}

mounts_scan() {
  if [[ $SV_IS_CONTAINER -eq 1 ]]; then
    sv_check skip mounts container "in a container, mounts belong to the host"
    return 0
  fi
  local target opts
  for target in /dev/shm /var/tmp /tmp; do
    # Only report on the ones this host asked for; /tmp and /var/tmp are
    # opt-in because installers and image builds run scripts out of them.
    case "$target" in
      /dev/shm) sv_bool mounts.dev-shm || { sv_check skip mounts devshm "/dev/shm hardening not requested"; continue; } ;;
      /var/tmp) sv_bool mounts.var-tmp || { sv_check skip mounts vartmp "/var/tmp hardening not requested"; continue; } ;;
      /tmp)     sv_bool mounts.tmp     || { sv_check skip mounts tmp "/tmp hardening not requested"; continue; } ;;
    esac
    opts="$(findmnt -no OPTIONS --target "$target" 2>/dev/null || true)"
    if [[ -z "$opts" ]]; then
      sv_check skip mounts "${target//\//}" "$target is not a separate mount"
      continue
    fi
    local lacking=""
    [[ "$opts" == *nosuid* ]] || lacking="$lacking nosuid"
    [[ "$opts" == *nodev* ]] || lacking="$lacking nodev"
    if [[ "$target" != "/tmp" ]] || sv_bool mounts.noexec-tmp; then
      [[ "$opts" == *noexec* ]] || lacking="$lacking noexec"
    fi
    if [[ -z "${lacking// /}" ]]; then
      sv_check pass mounts "${target//\//}" "$target is mounted with the hardened options"
    else
      sv_check fail mounts "${target//\//}" "$target is missing:$lacking"
    fi
  done
}

# ==========================================================================
# pam - password quality, lockout after repeated failures, ageing
# ==========================================================================
#
# Matters even with key-only SSH: sudo, console login and any service using
# PAM still take passwords.


pam_apply() {
  sv_header "pam"

  if sv_bool pam.pwquality; then
    sv_pkg_install libpam-pwquality || true
    sv_write_file pam /etc/security/pwquality.conf.d/99-securevps.conf 0644 <<EOF
$(sv_managed_header)
minlen = $(sv_int pam.min-length)
minclass = $(sv_int pam.min-classes)
dcredit = 0
ucredit = 0
lcredit = 0
ocredit = 0
maxrepeat = 3
gecoscheck = 1
dictcheck = 1
enforcing = 1
enforce_for_root
EOF
    # Older releases read only the single file, not the .d directory.
    if [[ -f /etc/security/pwquality.conf ]] && ! [[ -d /etc/security/pwquality.conf.d ]]; then
      sv_set_kv pam /etc/security/pwquality.conf minlen "$(sv_int pam.min-length)" " = "
      sv_set_kv pam /etc/security/pwquality.conf minclass "$(sv_int pam.min-classes)" " = "
    fi
    sv_ok "passwords need $(sv_int pam.min-length) characters from $(sv_int pam.min-classes) classes"
  fi

  if [[ "$(sv_int pam.remember)" -gt 0 ]]; then
    sv_ensure_line pam /etc/pam.d/common-password \
      "password	required			pam_pwhistory.so remember=$(sv_int pam.remember) use_authtok" \
      'pam_pwhistory\.so'
  fi

  if sv_bool pam.faillock; then
    sv_write_file pam /etc/security/faillock.conf 0644 <<EOF
$(sv_managed_header)
deny = $(sv_int pam.faillock-deny)
unlock_time = $(sv_int pam.faillock-unlock)
fail_interval = 900
even_deny_root
root_unlock_time = 60
audit
silent
EOF
    # On Debian and Ubuntu the pam-auth-update profile is the supported hook.
    if [[ -d /usr/share/pam-configs ]]; then
      sv_write_file pam /usr/share/pam-configs/securevps-faillock 0644 <<'EOF'
Name: securevps faillock
Default: yes
Priority: 1024
Auth-Type: Primary
Auth:
	[default=die]	pam_faillock.so authfail
	sufficient	pam_faillock.so authsucc
Auth-Initial:
	[default=die]	pam_faillock.so authfail
	sufficient	pam_faillock.so authsucc
Account-Type: Primary
Account:
	required	pam_faillock.so
Account-Initial:
	required	pam_faillock.so
EOF
      if [[ $SV_CHANGED -eq 1 ]] && ! sv_dry; then
        DEBIAN_FRONTEND=noninteractive pam-auth-update --package >/dev/null 2>&1 \
          || sv_warn "pam-auth-update failed, faillock may not be wired in"
      fi
    fi
    sv_ok "accounts lock for $(sv_int pam.faillock-unlock)s after $(sv_int pam.faillock-deny) failures"
  fi

  if sv_bool pam.login-defs; then
    sv_set_kv pam /etc/login.defs PASS_MAX_DAYS "$(sv_int pam.pass-max-days)" $'\t'
    sv_set_kv pam /etc/login.defs PASS_MIN_DAYS 1 $'\t'
    sv_set_kv pam /etc/login.defs PASS_WARN_AGE 14 $'\t'
    sv_set_kv pam /etc/login.defs ENCRYPT_METHOD YESCRYPT $'\t'
    sv_set_kv pam /etc/login.defs LOGIN_RETRIES 3 $'\t'
    sv_set_kv pam /etc/login.defs LOGIN_TIMEOUT 60 $'\t'
    sv_ok "password ageing and yescrypt hashing set in login.defs"
  fi

  if [[ "$(sv_int pam.tmout)" -gt 0 ]]; then
    sv_write_file pam /etc/profile.d/99-securevps-tmout.sh 0644 <<EOF
$(sv_managed_header)
TMOUT=$(sv_int pam.tmout)
readonly TMOUT
export TMOUT
EOF
    sv_ok "idle shells exit after $(sv_int pam.tmout)s"
  fi
  return 0
}

pam_scan() {
  local minlen
  minlen="$(grep -rhs '^minlen' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/ 2>/dev/null \
    | tail -1 | tr -dc '0-9' || true)"
  if [[ -n "$minlen" && "$minlen" -ge "$(sv_int pam.min-length)" ]]; then
    sv_check pass pam pwquality "minimum password length is $minlen"
  else
    sv_check fail pam pwquality "minimum password length is ${minlen:-unset}, wanted $(sv_int pam.min-length)"
  fi

  sv_verdict pam faillock \
    "faillock is wired into PAM" "no lockout after repeated authentication failures" \
    grep -rqs pam_faillock /etc/pam.d/

  local enc; enc="$(awk '/^ENCRYPT_METHOD/{print $2}' /etc/login.defs 2>/dev/null || true)"
  sv_expect pam hashing "password hashing" "${enc^^}" YESCRYPT SHA512

  local maxdays; maxdays="$(awk '/^PASS_MAX_DAYS/{print $2}' /etc/login.defs 2>/dev/null || true)"
  if [[ -n "$maxdays" && "$maxdays" -le "$(sv_int pam.pass-max-days)" ]]; then
    sv_check pass pam ageing "passwords expire after $maxdays days"
  else
    sv_check warn pam ageing "password maximum age is ${maxdays:-unset}"
  fi
}

# ==========================================================================
# services - stop and disable services a VPS rarely needs
# ==========================================================================
#
# Reports what is listening before touching anything, then stops the ones a
# server has no use for. Packages are disabled rather than removed unless
# --services-purge says otherwise.


readonly SV_SERVICES_DEFAULT="rpcbind avahi-daemon cups cups-browsed nfs-server \
inetd xinetd telnet vsftpd smbd nmbd snmpd rsh-server talk ldap slapd bind9"

services_list() {
  local list="$SV_SERVICES_DEFAULT"
  local extra; extra="$(sv_get services.extra)"
  [[ -n "$extra" ]] && list="$list ${extra//,/ }"
  local keep; keep="$(sv_get services.keep)"
  local s out=""
  for s in $list; do
    [[ -n "$keep" ]] && printf '%s\n' "${keep//,/ }" | tr ' ' '\n' | grep -qx "$s" && continue
    out="$out $s"
  done
  printf '%s' "${out# }"
}

services_apply() {
  sv_header "services"

  local s found=""
  for s in $(services_list); do
    sv_unit_exists "$s.service" || continue
    sv_unit_active "$s.service" || sv_unit_enabled "$s.service" || continue
    found="$found $s"
  done

  if [[ -z "${found// /}" ]]; then
    sv_ok "no unnecessary services are running"
  elif ! sv_bool services.disable; then
    sv_warn "these are running and could be disabled:$found"
  else
    sv_info "disabling:$found"
    for s in $found; do
      sv_svc_disable "$s.service"
      sv_bool services.purge && sv_pkg_purge "$s"
    done
    sv_ok "disabled:$found"
  fi

  # Postfix listening beyond loopback is the classic accidental open relay.
  if sv_unit_active postfix.service 2>/dev/null && sv_has_cmd postconf; then
    local iface; iface="$(postconf -h inet_interfaces 2>/dev/null || true)"
    if [[ "$iface" != "loopback-only" && "$iface" != "127.0.0.1"* ]]; then
      sv_note "Postfix listens on $iface. If this box only sends mail, set inet_interfaces = loopback-only."
    fi
  fi

  services_report_listening
  return 0
}

services_report_listening() {
  sv_has_cmd ss || return 0
  local lines
  lines="$(ss -Hltnp 2>/dev/null | awk '{print $4, $6}' | sed 's/users:((//; s/))$//' || true)"
  [[ -z "$lines" ]] && return 0
  sv_is_verbose && { sv_say "  listening sockets:"; printf '%s\n' "$lines" | sed 's/^/    /'; }
  return 0
}

services_scan() {
  local s running=""
  for s in $(services_list); do
    sv_unit_active "$s.service" 2>/dev/null && running="$running $s"
  done
  if [[ -z "${running// /}" ]]; then
    sv_check pass services unnecessary "no unnecessary services running"
  else
    sv_check fail services unnecessary "still running:$running"
  fi

  if sv_has_cmd ss; then
    local count
    count="$(ss -Hltn 2>/dev/null | awk '{print $4}' | grep -cE '^(0\.0\.0\.0|\[::\]|\*)' || true)"
    sv_check "$( [[ "${count:-0}" -le 2 ]] && printf pass || printf warn )" \
      services listening "${count:-0} socket(s) listening on every interface"
  fi
}

# ==========================================================================
# time - a correct clock, which TLS and log correlation depend on
# ==========================================================================
#
# Certificate validation and any attempt to line up two logs both fall apart
# on a drifting clock.


time_apply() {
  sv_header "time"

  local tz; tz="$(sv_get time.timezone)"
  if [[ -n "$tz" ]] && sv_has_cmd timedatectl; then
    if [[ "$(timedatectl show -p Timezone --value 2>/dev/null)" != "$tz" ]]; then
      if sv_dry; then sv_would "timedatectl set-timezone $tz"
      else
        if timedatectl set-timezone "$tz" 2>/dev/null; then
          sv_ok "timezone set to $tz"
        else
          sv_warn "could not set the timezone to $tz"
        fi
      fi
    else
      sv_skip "timezone already $tz"
    fi
  fi

  if sv_bool time.chrony; then
    if sv_pkg_install chrony; then
      local server; server="$(sv_get time.ntp-server)"
      if [[ -n "$server" ]]; then
        sv_write_file time /etc/chrony/conf.d/99-securevps.conf 0644 <<EOF
$(sv_managed_header)
server $server iburst
EOF
      fi
      sv_svc_disable systemd-timesyncd.service
      sv_svc_enable chrony.service || sv_svc_enable chronyd.service || true
      sv_ok "chrony is keeping the clock"
    fi
  else
    sv_svc_enable systemd-timesyncd.service || true
    sv_ok "systemd-timesyncd is keeping the clock"
  fi
  return 0
}

time_scan() {
  if sv_has_cmd timedatectl; then
    if timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -q yes; then
      sv_check pass time synced "the clock is synchronised"
    else
      sv_check fail time synced "the clock is not synchronised with any time source"
    fi
  fi
  if sv_unit_active chrony.service || sv_unit_active chronyd.service \
     || sv_unit_active systemd-timesyncd.service; then
    sv_check pass time daemon "a time daemon is running"
  else
    sv_check fail time daemon "no time daemon is running"
  fi
}

# ==========================================================================
# logging - logs that survive a reboot and an audit trail
# ==========================================================================
#
# Without a persistent journal the logs live in /run and are gone after a
# reboot, which is exactly when you want to read them. The audit ruleset
# stays light by default; the CIS set is verbose enough to fill a small disk.


logging_audit_rules_light() {
  cat <<'EOF'
## securevps.sh light ruleset. Enough to answer "who changed this and when"
## without the volume of the full CIS set.
-D
-b 8192
-f 1
--backlog_wait_time 60000

# Identity and authorisation.
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k privilege
-w /etc/sudoers.d/ -p wa -k privilege

# Remote access.
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /root/.ssh/ -p wa -k ssh_keys

# Anything that changes what the kernel is running.
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module,delete_module,finit_module -k modules

# Time changes, which is how a log is made to lie.
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time_change
-w /etc/localtime -p wa -k time_change

# Privilege escalation actually used.
-w /usr/bin/sudo -p x -k privilege_used
-w /var/log/sudo.log -p wa -k privilege_used

# Scheduled execution.
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/systemd/system/ -p wa -k systemd_units

# Make the rules themselves immutable until reboot.
-e 2
EOF
}

logging_audit_rules_cis() {
  logging_audit_rules_light | sed '/^-e 2$/d'
  cat <<'EOF'

## CIS additions: high volume, make sure /var/log has room.
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S open,openat,creat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b64 -S open,openat,creat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b64 -C euid!=uid -F euid=0 -F auid>=1000 -F auid!=unset -S execve -k privileged_exec
-e 2
EOF
}

logging_audit_rules() {
  case "$(sv_get logging.audit-rules)" in
    cis) logging_audit_rules_cis ;;
    *) logging_audit_rules_light ;;
  esac
}

logging_apply() {
  sv_header "logging"

  if sv_bool logging.journald; then
    sv_write_file logging /etc/systemd/journald.conf.d/99-securevps.conf 0644 <<EOF
$(sv_managed_header)
[Journal]
# Without this the journal lives in /run and is gone after a reboot, which is
# exactly when you want to read it.
Storage=persistent
Compress=yes
SystemMaxUse=$(sv_get logging.journal-max)
MaxRetentionSec=$(sv_get logging.journal-retention)
ForwardToSyslog=$( [[ -n "$(sv_get logging.remote-syslog)" ]] && printf yes || printf no )
EOF
    if [[ $SV_CHANGED -eq 1 ]] && ! sv_dry; then
      mkdir -p /var/log/journal
      systemd-tmpfiles --create --prefix /var/log/journal >/dev/null 2>&1 || true
      sv_svc_restart systemd-journald.service || true
    fi
    sv_ok "journal is persistent, capped at $(sv_get logging.journal-max)"
  fi

  local remote; remote="$(sv_get logging.remote-syslog)"
  if [[ -n "$remote" ]]; then
    sv_pkg_install rsyslog || true
    sv_write_file logging /etc/rsyslog.d/99-securevps-remote.conf 0644 <<EOF
$(sv_managed_header)
# Ship to a collector, because logs on a compromised host are evidence under
# the attacker's control.
*.* action(type="omfwd" target="${remote%%:*}" port="$( [[ "$remote" == *:* ]] && printf '%s' "${remote##*:}" || printf 514 )"
  protocol="tcp" queue.type="linkedlist" queue.filename="securevps_fwd"
  action.resumeRetryCount="-1" queue.saveOnShutdown="on")
EOF
    sv_svc_restart rsyslog.service || true
    sv_ok "syslog forwarded to $remote"
  fi

  local rules; rules="$(sv_get logging.audit-rules)"
  if sv_bool logging.auditd && [[ "$rules" != none ]]; then
    if [[ $SV_IS_CONTAINER -eq 1 ]]; then
      sv_skip "auditd needs a host kernel, skipping in a container"
    elif sv_pkg_install auditd audispd-plugins; then
      sv_write_gen logging /etc/audit/rules.d/99-securevps.rules 0640 logging_audit_rules
      if [[ $SV_CHANGED -eq 1 ]] && ! sv_dry; then
        augenrules --load >/dev/null 2>&1 || sv_warn "augenrules could not load the new rules"
      fi
      sv_svc_enable auditd.service || true
      sv_ok "auditd running with the $rules ruleset"
      [[ "$rules" == cis ]] && sv_note "The CIS audit ruleset is verbose. Watch /var/log/audit and raise space_left_action if the disk fills."
    fi
  else
    sv_skip "auditd not requested"
  fi
  return 0
}

logging_scan() {
  sv_verdict logging persistent \
    "the journal survives a reboot" "the journal is in /run and is lost on reboot" \
    test -d /var/log/journal

  if [[ $SV_IS_CONTAINER -eq 1 ]]; then
    sv_check skip logging auditd "auditd needs a host kernel"
  elif sv_unit_active auditd.service; then
    sv_check pass logging auditd "auditd is running"
    if sv_has_cmd auditctl; then
      local n; n="$(auditctl -l 2>/dev/null | grep -cv 'No rules' || true)"
      if [[ "${n:-0}" -gt 5 ]]; then
        sv_check pass logging audit-rules "$n audit rules loaded"
      else
        sv_check fail logging audit-rules "only ${n:-0} audit rules loaded"
      fi
    fi
  else
    sv_check fail logging auditd "auditd is not running"
  fi
}

# ==========================================================================
# apparmor - AppArmor profiles in enforce rather than complain mode
# ==========================================================================
#
# A profile in complain mode logs what it would have blocked and blocks
# nothing, which is worth roughly nothing on its own.


apparmor_apply() {
  sv_header "apparmor"
  if [[ $SV_IS_CONTAINER -eq 1 ]]; then
    sv_skip "running in a container, AppArmor belongs to the host"
    return 0
  fi

  sv_pkg_install apparmor apparmor-utils || { sv_warn "AppArmor is not available"; return 1; }
  sv_svc_enable apparmor.service || true

  if ! sv_bool apparmor.enforce; then
    sv_skip "leaving profiles in whatever mode they are in"
    return 0
  fi

  if sv_dry; then sv_would "put every complain-mode profile into enforce"; return 0; fi
  sv_has_cmd aa-status || { sv_warn "aa-status missing"; return 1; }

  local complain; complain="$(aa-status --complaining 2>/dev/null || echo 0)"
  if [[ "${complain:-0}" -eq 0 ]]; then
    sv_ok "all profiles already enforcing"
    return 0
  fi

  local p
  while read -r p; do
    [[ -z "$p" ]] && continue
    aa-enforce "$p" >/dev/null 2>&1 || sv_debug "could not enforce $p"
  done <<< "$(aa-status --json 2>/dev/null \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print("\n".join(k for k,v in d.get("profiles",{}).items() if v=="complain"))' 2>/dev/null || true)"

  sv_ok "moved $complain profile(s) from complain to enforce"
  sv_note "AppArmor is enforcing. If an application starts failing on file access, check: journalctl -k | grep apparmor"
  return 0
}

apparmor_scan() {
  if [[ $SV_IS_CONTAINER -eq 1 ]]; then
    sv_check skip apparmor container "AppArmor belongs to the host"
    return 0
  fi
  if ! sv_has_cmd aa-status; then
    sv_check fail apparmor installed "AppArmor tools are not installed"
    return 0
  fi
  if ! aa-status --enabled 2>/dev/null; then
    sv_check fail apparmor enabled "AppArmor is not enabled in the kernel"
    return 0
  fi
  sv_check pass apparmor enabled "AppArmor is enabled"
  local enforcing complaining
  enforcing="$(aa-status --enforced 2>/dev/null || echo 0)"
  complaining="$(aa-status --complaining 2>/dev/null || echo 0)"
  if [[ "${complaining:-0}" -eq 0 ]]; then
    sv_check pass apparmor enforce "all ${enforcing:-0} profiles are enforcing"
  else
    sv_check fail apparmor enforce "${complaining} profile(s) only complain, they do not block"
  fi
}

# ==========================================================================
# banner - a legal warning banner, and no OS version before login
# ==========================================================================
#
# The stock /etc/issue.net prints the distribution and kernel version to
# anyone who opens a connection, which is free reconnaissance.


banner_text() {
  local f; f="$(sv_get banner.file)"
  if [[ -n "$f" && -f "$f" ]]; then cat "$f"; return 0; fi
  cat <<'EOF'
###############################################################################
                            AUTHORISED ACCESS ONLY

  This system is private property. Access is permitted only to people who
  have been given it explicitly, for the purposes it was given for.

  All connections and commands are logged. Unauthorised use may be reported
  to law enforcement. Disconnect now if you are not an authorised user.
###############################################################################
EOF
}

banner_apply() {
  sv_header "banner"

  if sv_bool banner.issue; then
    # /etc/issue.net is what sshd shows before authentication. The stock file
    # prints the distribution and kernel version, which is free reconnaissance.
    sv_write_gen banner /etc/issue.net 0644 banner_text
    sv_write_gen banner /etc/issue 0644 banner_text
    sv_ok "pre-login banner installed, OS version no longer advertised"
  fi

  if sv_bool banner.motd; then
    local d
    for d in /etc/update-motd.d/10-help-text /etc/update-motd.d/50-motd-news \
             /etc/update-motd.d/51-cloudguest /etc/update-motd.d/00-header; do
      [[ -f "$d" ]] || continue
      if sv_dry; then sv_would "chmod -x $d"
      else
        chmod -x "$d"
        sv_record custom banner "$d" "chmod +x to restore"
      fi
    done
    sv_write_gen banner /etc/motd 0644 banner_text
    sv_ok "login message replaced"
  fi
  return 0
}

banner_scan() {
  sv_verdict banner issue-net \
    "a warning banner is shown before login" "no warning banner before login" \
    grep -qsi 'authorised\|authorized' /etc/issue.net
  sv_verdict banner os-disclosure \
    "no OS version disclosed before login" "/etc/issue.net still expands the OS version" \
    sv_not grep -qsE '\\[a-zA-Z]' /etc/issue.net
  local v; v="$(sv_sshd_get debianbanner 2>/dev/null || true)"
  if [[ "$v" == "no" ]]; then
    sv_check pass banner sshd-version "sshd does not advertise the distribution patch level"
  elif [[ -n "$v" ]]; then
    sv_check warn banner sshd-version "sshd advertises its Debian version string"
  fi
}

# ==========================================================================
# integrity - AIDE, so you can tell what changed on disk (off by default)
# ==========================================================================
#
# Off by default because the first run takes minutes and the daily mail is
# noise unless somebody reads it. Worth knowing: the database sits on the
# same host it is checking, so copy it somewhere else or an attacker with
# root rewrites both.


integrity_apply() {
  sv_header "integrity"
  if ! sv_bool integrity.enable; then
    sv_skip "not requested, enable with --integrity-enable"
    return 0
  fi

  sv_pkg_install aide aide-common || { sv_warn "AIDE is not available"; return 1; }

  sv_write_file integrity /etc/aide/aide.conf.d/99-securevps.conf 0644 <<'EOF'
# Managed by securevps.sh. Directories that change constantly produce noise
# nobody reads, so they are excluded here rather than ignored in practice.
!/var/log/.*
!/var/lib/docker/.*
!/var/lib/containerd/.*
!/var/cache/.*
!/var/spool/.*
!/var/tmp/.*
!/tmp/.*
!/proc/.*
!/sys/.*
!/run/.*
EOF

  sv_write_file integrity /etc/systemd/system/securevps-aide.service 0644 <<EOF
$(sv_managed_header)
[Unit]
Description=securevps.sh AIDE integrity check

[Service]
Type=oneshot
Nice=19
IOSchedulingClass=idle
ExecStart=/usr/bin/aide --check --config /etc/aide/aide.conf
EOF

  sv_timer_unit integrity securevps-aide \
    "securevps.sh AIDE integrity check" "$(sv_get integrity.schedule)"

  if sv_dry; then
    sv_would "build the AIDE database, which takes several minutes"
    return 0
  fi

  systemctl daemon-reload >/dev/null 2>&1 || true
  sv_svc_enable securevps-aide.timer || true

  if [[ ! -f /var/lib/aide/aide.db ]]; then
    sv_info "building the AIDE database, this takes a few minutes on a first run"
    if aideinit -y -f >/dev/null 2>&1 || aide --init --config /etc/aide/aide.conf >/dev/null 2>&1; then
      [[ -f /var/lib/aide/aide.db.new ]] && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
      sv_ok "AIDE database built"
    else
      sv_warn "AIDE database build failed"
      return 1
    fi
  else
    sv_skip "AIDE database already exists"
  fi
  sv_note "AIDE compares against a database stored on this same host. An attacker with root can rewrite both. Copy /var/lib/aide/aide.db somewhere else for it to mean anything."
  return 0
}

integrity_scan() {
  if ! sv_bool integrity.enable; then
    sv_check skip integrity aide "file integrity monitoring not requested"
    return 0
  fi
  sv_verdict integrity aide "AIDE database present" "AIDE has no baseline database" \
    test -f /var/lib/aide/aide.db
  sv_verdict integrity schedule \
    "integrity checks are scheduled" "integrity checks are not scheduled" \
    sv_unit_enabled securevps-aide.timer
}

# ==========================================================================
# mfa - a TOTP code on top of the SSH key (off by default)
# ==========================================================================
#
# Required in addition to the key, never instead of it. Name a deploy
# account with --mfa-exempt-user so automation keeps working.


mfa_render_sshd() {
  local exempt; exempt="$(sv_get mfa.exempt-user)"
  sv_managed_header
  printf '\nKbdInteractiveAuthentication yes\n'
  printf 'AuthenticationMethods publickey,keyboard-interactive:pam\n'
  if [[ -n "$exempt" ]]; then
    printf '\n# Named accounts keep key-only login so automation does not break.\n'
    printf 'Match User %s\n' "$exempt"
    printf '    AuthenticationMethods publickey\n'
  fi
}

mfa_apply() {
  sv_header "mfa"
  if ! sv_bool mfa.enable; then
    sv_skip "not requested, enable with --mfa-enable"
    return 0
  fi
  if sv_bool ssh.disable-pam; then
    sv_err "MFA needs PAM, but ssh.disable-pam is set. Pick one."
    return 1
  fi

  sv_pkg_install libpam-google-authenticator || return 1

  sv_write_file mfa /etc/pam.d/sshd.securevps-mfa 0644 <<EOF
$(sv_managed_header)
# Included from /etc/pam.d/sshd. nullok means an account without an enrolled
# secret still gets in; drop it once everyone has enrolled.
auth required pam_google_authenticator.so nullok
EOF

  sv_ensure_line mfa /etc/pam.d/sshd \
    "@include sshd.securevps-mfa" \
    'sshd\.securevps-mfa'

  # sshd must be told to run the keyboard-interactive stage after the key.
  local exempt; exempt="$(sv_get mfa.exempt-user)"
  sv_write_gen mfa /etc/ssh/sshd_config.d/98-securevps-mfa.conf 0600 mfa_render_sshd

  if ! sv_dry; then
    if ! sv_validate "sshd config with MFA" sshd -t; then
      sv_remove_file mfa /etc/ssh/sshd_config.d/98-securevps-mfa.conf
      sv_err "sshd rejected the MFA config, reverted"
      return 1
    fi
    sv_svc_reload "$(sv_sshd_unit)" || true
  fi

  sv_ok "TOTP required in addition to the SSH key"
  sv_note "Nobody has a TOTP secret yet. Each user must run 'google-authenticator' once. Until they do, nullok lets them in without a code."
  [[ -n "$exempt" ]] && sv_note "These users keep key-only login: $exempt"
  return 0
}

mfa_scan() {
  if ! sv_bool mfa.enable; then
    sv_check skip mfa totp "second factor not requested"
    return 0
  fi
  sv_verdict mfa totp \
    "TOTP is wired into the SSH PAM stack" "TOTP is not wired into PAM" \
    grep -rqs pam_google_authenticator /etc/pam.d/
  if [[ "$(sv_sshd_get authenticationmethods)" == *keyboard-interactive* ]]; then
    sv_check pass mfa sshd "sshd asks for a second factor"
  else
    sv_check fail mfa sshd "sshd does not ask for a second factor"
  fi
}

# ==========================================================================
# vpn - WireGuard or Tailscale, so SSH need not face the internet
# ==========================================================================
#
# The strongest single change available: a port that never appears in a
# public scan does not get brute forced. Keep a provider console session
# available, because the VPN becomes a dependency of your access.


vpn_apply() {
  sv_header "vpn"
  case "$(sv_get vpn.provider)" in
    none)
      sv_skip "no VPN requested"
      sv_note "The strongest single change you can make is taking SSH off the public internet: --vpn-provider tailscale or wireguard."
      return 0
      ;;
    tailscale)
      if ! sv_has_cmd tailscale; then
        if sv_dry; then sv_would "install tailscale from pkgs.tailscale.com"
        else
          sv_info "installing Tailscale"
          curl -fsSL https://tailscale.com/install.sh | sh >/dev/null 2>&1 \
            || { sv_warn "Tailscale install failed"; return 1; }
        fi
      fi
      local key; key="$(sv_get vpn.tailscale-authkey)"
      if [[ -n "$key" ]] && ! sv_dry; then
        tailscale up --auth-key "$key" --ssh=false >/dev/null 2>&1 \
          || sv_warn "tailscale up failed"
        sv_ok "joined the tailnet"
      else
        sv_note "Run 'tailscale up' to join your tailnet, then re-run with --vpn-ssh-vpn-only."
      fi
      ;;
    wireguard)
      sv_pkg_install wireguard wireguard-tools || return 1
      if [[ ! -f /etc/wireguard/wg0.conf ]] && ! sv_dry; then
        umask 077
        local priv pub
        priv="$(wg genkey)"; pub="$(printf '%s' "$priv" | wg pubkey)"
        sv_write_file vpn /etc/wireguard/wg0.conf 0600 <<EOF
$(sv_managed_header)
# Add a [Peer] block per client, then: systemctl enable --now wg-quick@wg0
[Interface]
Address = 10.88.0.1/24
ListenPort = $(sv_int vpn.wg-port)
PrivateKey = $priv

# [Peer]
# PublicKey = <client public key>
# AllowedIPs = 10.88.0.2/32
EOF
        sv_ok "WireGuard key generated, server public key: $pub"
        sv_note "WireGuard is configured but has no peers yet. Add a [Peer] block to /etc/wireguard/wg0.conf, then: systemctl enable --now wg-quick@wg0"
      else
        sv_skip "/etc/wireguard/wg0.conf already exists"
      fi
      ;;
    *) sv_err "unknown VPN provider: $(sv_get vpn.provider)"; return 1 ;;
  esac

  if sv_bool vpn.ssh-vpn-only; then
    local iface addr
    case "$(sv_get vpn.provider)" in
      tailscale) iface=tailscale0 ;;
      wireguard) iface=wg0 ;;
    esac
    addr="$(ip -4 -o addr show "$iface" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 || true)"
    if [[ -z "$addr" ]]; then
      sv_err "$iface has no address yet, so restricting SSH to it would lock you out. Bring the VPN up first."
      return 1
    fi
    sv_write_file vpn /etc/ssh/sshd_config.d/97-securevps-vpn.conf 0600 <<EOF
$(sv_managed_header)
# sshd binds only to the VPN address. Port $(sv_int ssh.port) stops answering
# on the public interface entirely.
ListenAddress $addr
EOF
    if ! sv_dry; then
      if sv_validate "sshd bound to $iface" sshd -t; then
        sv_svc_restart "$(sv_sshd_unit)" || true
        sv_ok "sshd now answers only on $addr ($iface)"
        sv_note "SSH is reachable only over the VPN. Keep a provider console session available in case the VPN goes down."
      else
        sv_remove_file vpn /etc/ssh/sshd_config.d/97-securevps-vpn.conf
        return 1
      fi
    fi
  fi
  return 0
}

vpn_scan() {
  local provider; provider="$(sv_get vpn.provider)"
  if [[ "$provider" == none ]]; then
    sv_check skip vpn provider "no VPN configured"
    return 0
  fi
  case "$provider" in
    tailscale)
      if sv_has_cmd tailscale && tailscale status >/dev/null 2>&1; then
        sv_check pass vpn tailscale "connected to the tailnet"
      else
        sv_check fail vpn tailscale "Tailscale is not connected"
      fi
      ;;
    wireguard)
      if sv_has_cmd wg && [[ -n "$(wg show 2>/dev/null)" ]]; then
        sv_check pass vpn wireguard "WireGuard is up"
      else
        sv_check fail vpn wireguard "WireGuard is not up"
      fi
      ;;
  esac
  local listen; listen="$(sv_sshd_get listenaddress || true)"
  if [[ -n "$listen" && "$listen" != "0.0.0.0"* && "$listen" != "::"* ]]; then
    sv_check pass vpn ssh-scope "sshd listens only on $listen"
  else
    sv_check warn vpn ssh-scope "sshd still answers on every interface"
  fi
}

# ==========================================================================
# alerts - tell someone when a person logs in (off by default)
# ==========================================================================
#
# A PAM hook on every interactive session. Cheap, and the first thing that
# tells you a key has been copied.


alerts_apply() {
  sv_header "alerts"
  if ! sv_bool alerts.login-alert; then
    sv_skip "not requested, enable with --alerts-login-alert"
    return 0
  fi
  local email webhook
  email="$(sv_get alerts.email)"; webhook="$(sv_get alerts.webhook)"
  if [[ -z "$email" && -z "$webhook" ]]; then
    sv_err "login alerts need somewhere to go: --alerts-email or --alerts-webhook"
    return 1
  fi

  sv_write_file alerts /usr/local/sbin/securevps-login-alert 0750 <<EOF
#!/bin/sh
# Written by securevps.sh. Called by PAM on every interactive session open.
[ "\$PAM_TYPE" = "open_session" ] || exit 0
case "\$PAM_SERVICE" in sshd|login) ;; *) exit 0 ;; esac

host="\$(hostname -f 2>/dev/null || hostname)"
subject="SSH login: \$PAM_USER@\$host from \$PAM_RHOST"
body="user:    \$PAM_USER
from:    \$PAM_RHOST
service: \$PAM_SERVICE
host:    \$host
when:    \$(date -u '+%Y-%m-%d %H:%M:%S UTC')"

$( # shellcheck disable=SC2016  # \$body and \$subject belong to the generated script
   [[ -n "$email" ]] && printf 'printf "%%s\\n" "$body" | mail -s "$subject" %s 2>/dev/null || true' "$email" )
$( # shellcheck disable=SC2016  # \$subject belongs to the generated script
   [[ -n "$webhook" ]] && printf 'command -v curl >/dev/null && curl -fsS -m 10 -X POST -H "Content-Type: application/json" -d "{\\"text\\":\\"\$subject\\"}" %s >/dev/null 2>&1 || true' "$webhook" )
exit 0
EOF

  sv_ensure_line alerts /etc/pam.d/sshd \
    "session optional pam_exec.so seteuid /usr/local/sbin/securevps-login-alert" \
    'securevps-login-alert'

  [[ -n "$email" ]] && { sv_pkg_install bsd-mailx || sv_warn "no mail command, email alerts will not send"; }
  sv_ok "login alerts going to ${email:-$webhook}"
  return 0
}

alerts_scan() {
  if ! sv_bool alerts.login-alert; then
    sv_check skip alerts login "login alerts not requested"
    return 0
  fi
  sv_verdict alerts login \
    "login alerts are wired into PAM" "login alerts are not wired into PAM" \
    grep -qs securevps-login-alert /etc/pam.d/sshd
}

# ==========================================================================
# backup - restic and a timer, pointed at a repository you supply
# ==========================================================================
#
# Will not invent a destination. A backup you have never restored is a
# hypothesis, so run a restore into /tmp once and look at what comes back.


backup_apply() {
  sv_header "backup"
  if ! sv_bool backup.enable; then
    sv_skip "not requested, enable with --backup-enable --backup-repo ..."
    return 0
  fi
  local repo pwfile
  repo="$(sv_get backup.repo)"; pwfile="$(sv_get backup.password-file)"
  if [[ -z "$repo" ]]; then
    sv_err "--backup-repo is required, this script will not invent a destination"
    return 1
  fi
  if [[ -z "$pwfile" ]]; then
    pwfile=/etc/securevps/restic-password
    sv_note "No --backup-password-file given. Put the repository password in $pwfile (mode 0600) before the first run."
  fi

  sv_pkg_install restic || return 1

  sv_write_file backup /etc/securevps/backup.env 0600 <<EOF
$(sv_managed_header)
RESTIC_REPOSITORY=$repo
RESTIC_PASSWORD_FILE=$pwfile
EOF

  sv_write_file backup /etc/systemd/system/securevps-backup.service 0644 <<EOF
$(sv_managed_header)
[Unit]
Description=securevps.sh restic backup
After=network-online.target

[Service]
Type=oneshot
Nice=19
IOSchedulingClass=idle
EnvironmentFile=/etc/securevps/backup.env
ExecStart=/usr/bin/restic backup --one-file-system --exclude-caches /etc /home /root /var/lib
ExecStartPost=/usr/bin/restic forget --prune --keep-daily 7 --keep-weekly 4 --keep-monthly 6
EOF

  sv_timer_unit backup securevps-backup \
    "securevps.sh restic backup" "$(sv_get backup.schedule)"

  if ! sv_dry; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    sv_svc_enable securevps-backup.timer || true
  fi
  sv_ok "restic backups scheduled $(sv_get backup.schedule) to $repo"
  sv_note "A backup you have never restored is a hypothesis. Run 'restic restore latest --target /tmp/restore-test' once and look at what comes back."
  return 0
}

backup_scan() {
  if ! sv_bool backup.enable; then
    sv_check skip backup timer "backups not configured here"
    return 0
  fi
  sv_verdict backup timer "backup timer is enabled" "backup timer is not enabled" \
    sv_unit_enabled securevps-backup.timer
  sv_verdict backup configured \
    "restic is installed and configured" "restic is not configured" \
    test -f /etc/securevps/backup.env
}


# --------------------------------------------------------------------------
# 9. argument parsing
# --------------------------------------------------------------------------

sv_is_module() {
  local m
  for m in "${SV_MODULE_ORDER[@]}"; do [[ "$m" == "$1" ]] && return 0; done
  return 1
}

# Turn a flag into a CFG key. "--ssh-port" is ssh.port. Inside a single-module
# run, "--port" is too. Returns empty when nothing matches.
sv_flag_to_key() {
  local flag="${1#--}" candidate
  # Explicit module prefix.
  local head="${flag%%-*}" tail="${flag#*-}"
  if [[ "$flag" == *-* ]] && sv_is_module "$head" && [[ -n "${OPT_TYPE[$head.$tail]-}" ]]; then
    printf '%s' "$head.$tail"; return 0
  fi
  # Bare core option.
  if [[ -n "${OPT_TYPE[core.$flag]-}" ]]; then printf '%s' "core.$flag"; return 0; fi
  # Short form inside a single-module run.
  if [[ -n "$SV_ACTIVE_MODULE" && -n "${OPT_TYPE[$SV_ACTIVE_MODULE.$flag]-}" ]]; then
    printf '%s' "$SV_ACTIVE_MODULE.$flag"; return 0
  fi
  # Unambiguous match across every module, so --engine works anywhere.
  local key hits=0
  for key in "${OPT_ORDER[@]}"; do
    [[ "${key#*.}" == "$flag" ]] || continue
    candidate="$key"; hits=$((hits + 1))
  done
  [[ $hits -eq 1 ]] && { printf '%s' "$candidate"; return 0; }
  printf ''
  return 1
}

sv_is_command() {
  case "$1" in
    harden|scan|revert|confirm|help) return 0 ;;
  esac
  sv_is_module "$1"
}

sv_take_command() {
  SV_CMD="$1"
  SV_CMD_GIVEN=1
  sv_is_module "$SV_CMD" && SV_ACTIVE_MODULE="$SV_CMD"
  return 0
}

sv_parse_args() {
  local -a rest=()
  local arg key next
  SV_CMD="harden"
  SV_CMD_GIVEN=0

  # The command usually comes first, but "securevps.sh --profile minimal
  # harden" is a reasonable thing to type, so a bare word anywhere in the
  # arguments is accepted as the command until one has been seen.
  if [[ $# -gt 0 && "$1" != -* ]]; then
    sv_is_command "$1" || sv_die "unknown command: $1. Try: securevps.sh help"
    sv_take_command "$1"; shift
  fi

  # revert takes bare module names.
  if [[ "$SV_CMD" == "revert" ]]; then
    while [[ $# -gt 0 && "$1" != -* ]]; do SV_REVERT_TARGETS+=("$1"); shift; done
  fi

  while [[ $# -gt 0 ]]; do
    arg="$1"
    case "$arg" in
      -h|--help) SV_CMD="help"; shift; continue ;;
      -V|--version) printf 'securevps.sh %s\n' "$SV_VERSION"; exit 0 ;;
      -n) arg="--dry-run" ;;
      -y) arg="--yes" ;;
      -v) arg="--verbose" ;;
      -q) arg="--quiet" ;;
      --) shift; rest+=("$@"); break ;;
    esac

    if [[ "$arg" != --* ]]; then
      if [[ $SV_CMD_GIVEN -eq 0 ]] && sv_is_command "$arg"; then
        sv_take_command "$arg"; shift
        if [[ "$SV_CMD" == "revert" ]]; then
          while [[ $# -gt 0 && "$1" != -* ]]; do SV_REVERT_TARGETS+=("$1"); shift; done
        fi
        continue
      fi
      rest+=("$arg"); shift; continue
    fi

    # --key=value
    if [[ "$arg" == *=* ]]; then
      key="$(sv_flag_to_key "${arg%%=*}")" || true
      [[ -z "$key" ]] && sv_die "unknown option: ${arg%%=*}. Try: securevps.sh help"
      sv_set "$key" "${arg#*=}"
      shift; continue
    fi

    # --no-<bool>
    if [[ "$arg" == --no-* ]]; then
      key="$(sv_flag_to_key "--${arg#--no-}")" || true
      if [[ -n "$key" && "${OPT_TYPE[$key]}" == bool ]]; then
        sv_set "$key" false; shift; continue
      fi
    fi

    key="$(sv_flag_to_key "$arg")" || true
    [[ -z "$key" ]] && sv_die "unknown option: $arg. Try: securevps.sh help"

    if [[ "${OPT_TYPE[$key]}" == bool ]]; then
      # A bool may still be given an explicit value: --ssh-tcp-forwarding true
      next="${2-}"
      if [[ "$next" =~ ^(true|false|yes|no|on|off|1|0)$ ]]; then
        sv_set "$key" "$next"; shift 2
      else
        sv_set "$key" true; shift
      fi
    else
      [[ $# -ge 2 ]] || sv_die "$arg needs a value"
      sv_set "$key" "$2"; shift 2
    fi
  done

  if [[ ${#rest[@]} -gt 0 ]]; then
    if sv_is_command "${rest[0]}"; then
      sv_die "two commands given: $SV_CMD and ${rest[0]}"
    fi
    sv_die "unexpected argument: ${rest[0]}. Try: securevps.sh help"
  fi
  return 0
}


# --------------------------------------------------------------------------
# 10. dispatch
# --------------------------------------------------------------------------

sv_profile_modules() {
  case "$(sv_get core.profile)" in
    core) printf '%s\n' "${SV_PROFILE_CORE[@]}" ;;
    minimal) printf '%s\n' "${SV_PROFILE_MINIMAL[@]}" ;;
    standard) printf '%s\n' "${SV_PROFILE_STANDARD[@]}" ;;
    *) sv_die "unknown profile: $(sv_get core.profile). Pick core, minimal or standard." ;;
  esac
}

sv_resolve_modules() {
  local -a chosen=()
  local only skip m
  only="$(sv_get core.only)"; skip="$(sv_get core.skip)"

  if [[ -n "$only" ]]; then
    for m in ${only//,/ }; do
      sv_is_module "$m" || sv_die "unknown module: $m"
      chosen+=("$m")
    done
  else
    mapfile -t chosen <<< "$(sv_profile_modules)"
  fi

  SV_RUN_MODULES=()
  for m in "${SV_MODULE_ORDER[@]}"; do
    printf '%s\n' "${chosen[@]}" | grep -qx "$m" || continue
    if [[ -n "$skip" ]] && printf '%s\n' "${skip//,/ }" | tr ' ' '\n' | grep -qx "$m"; then
      sv_debug "skipping $m"
      continue
    fi
    SV_RUN_MODULES+=("$m")
  done
}

sv_cmd_harden() {
  sv_require_root
  sv_resolve_modules
  [[ ${#SV_RUN_MODULES[@]} -eq 0 ]] && sv_die "no modules selected"

  sv_run_init
  sv_say "${C_BOLD}securevps.sh $SV_VERSION${C_RESET} on $SV_OS_PRETTY"
  sv_say "profile $(sv_get core.profile), modules: ${SV_RUN_MODULES[*]}"
  sv_dry && sv_say "${C_YELLOW}dry run, nothing will be written${C_RESET}"
  [[ -n "$SV_BACKUP_DIR" ]] && sv_say "backups: $SV_BACKUP_DIR"

  local m failed=() total_changes=0
  for m in "${SV_RUN_MODULES[@]}"; do
    SV_MODULE_CHANGES=0
    if "${m}_apply"; then
      sv_debug "$m made $SV_MODULE_CHANGES change(s)"
    else
      failed+=("$m")
      sv_warn "module $m did not finish"
    fi
    total_changes=$((total_changes + SV_MODULE_CHANGES))
  done

  sv_say ""
  sv_header "summary"
  if sv_dry; then
    sv_say "Dry run finished. Run without --dry-run to apply."
  else
    sv_say "$total_changes change(s) across ${#SV_RUN_MODULES[@]} module(s)."
    sv_say "Undo everything from this run with: securevps.sh revert --run $SV_RUN_ID"
  fi

  if [[ ${#SV_NOTES[@]} -gt 0 ]]; then
    sv_say ""
    sv_say "${C_BOLD}Worth reading before you close this session:${C_RESET}"
    local n
    for n in "${SV_NOTES[@]}"; do
      printf '  %s %s\n' "${C_YELLOW}*${C_RESET}" "$n"
    done
  fi

  [[ $SV_REBOOT_REQUIRED -eq 1 ]] && sv_say "" && sv_warn "A reboot is needed to finish applying updates."

  if [[ ${#failed[@]} -gt 0 ]]; then
    sv_say ""
    sv_err "modules that failed: ${failed[*]}"
    return 1
  fi
  sv_say ""
  sv_say "Check the result with: ${C_BOLD}securevps.sh scan${C_RESET}"
  return 0
}

sv_cmd_module() {
  local m="$1"
  sv_require_root
  sv_run_init
  sv_dry && sv_say "${C_YELLOW}dry run, nothing will be written${C_RESET}"
  SV_MODULE_CHANGES=0
  local rc=0
  "${m}_apply" || rc=1
  if [[ ${#SV_NOTES[@]} -gt 0 ]]; then
    sv_say ""
    local n
    for n in "${SV_NOTES[@]}"; do printf '  %s %s\n' "${C_YELLOW}*${C_RESET}" "$n"; done
  fi
  return $rc
}

sv_cmd_scan() {
  sv_resolve_modules
  local -a mods=("${SV_RUN_MODULES[@]}")
  [[ -n "$SV_ACTIVE_MODULE" ]] && mods=("$SV_ACTIVE_MODULE")

  sv_is_json || sv_say "${C_BOLD}securevps.sh scan${C_RESET} on $SV_OS_PRETTY"
  sv_is_json || sv_say ""

  local m
  for m in "${mods[@]}"; do "${m}_scan" || true; done

  if sv_is_json; then
    printf '{\n  "version": "%s",\n  "host": "%s",\n  "os": "%s",\n' \
      "$SV_VERSION" "$(hostname)" "$(sv_json_escape "$SV_OS_PRETTY")"
    printf '  "summary": {"pass": %d, "fail": %d, "warn": %d, "skip": %d},\n' \
      "$SV_SCAN_PASS" "$SV_SCAN_FAIL" "$SV_SCAN_WARN" "$SV_SCAN_SKIP"
    printf '  "checks": [\n'
    local i
    for i in "${!SV_SCAN_JSON[@]}"; do
      printf '    %s%s\n' "${SV_SCAN_JSON[$i]}" \
        "$( [[ $i -lt $((${#SV_SCAN_JSON[@]} - 1)) ]] && printf ',' )"
    done
    printf '  ]\n}\n'
  else
    sv_say ""
    printf '  %s %d   %s %d   %s %d   %s %d\n' \
      "${C_GREEN}pass${C_RESET}" "$SV_SCAN_PASS" \
      "${C_RED}fail${C_RESET}" "$SV_SCAN_FAIL" \
      "${C_YELLOW}warn${C_RESET}" "$SV_SCAN_WARN" \
      "${C_DIM}skip${C_RESET}" "$SV_SCAN_SKIP"
    if [[ $SV_SCAN_FAIL -gt 0 ]]; then
      sv_say ""
      sv_say "Fix them with: ${C_BOLD}securevps.sh harden${C_RESET}"
    fi
  fi

  [[ $SV_SCAN_FAIL -gt 0 ]] && return 1
  return 0
}

# Undo one run's manifest, newest entry first. The tally goes in a global
# rather than on stdout, because the restore messages go there too and a
# "$(...)" capture would feed them into the arithmetic.
SV_REVERT_COUNT=0
sv_revert_run() {
  local dir="$1" filter="$2"
  [[ -f "$dir/manifest.tsv" ]] || { sv_warn "$(basename "$dir") has no manifest"; return 0; }
  local action module path stored
  while IFS=$'\t' read -r action module path stored; do
    [[ "$action" == \#* || -z "$action" ]] && continue
    # shellcheck disable=SC2086  # deliberate word splitting
    if [[ -n "$filter" ]] && ! printf '%s\n' $filter | grep -qx "$module"; then continue; fi
    if [[ "$action" == custom ]]; then
      sv_warn "$module made a change that cannot be undone automatically: $path ${stored:+($stored)}"
      continue
    fi
    sv_revert_entry "$action" "$module" "$path" "$stored" "$dir"
    SV_REVERT_COUNT=$((SV_REVERT_COUNT + 1))
  done <<< "$(tac "$dir/manifest.tsv")"
  return 0
}

sv_cmd_revert() {
  sv_require_root
  local filter=""
  [[ ${#SV_REVERT_TARGETS[@]} -gt 0 ]] && filter="${SV_REVERT_TARGETS[*]}"

  local -a runs=()
  if [[ -n "${SV_REVERT_RUN:-}" ]]; then
    [[ -d "$SV_BACKUP_ROOT/$SV_REVERT_RUN" ]] || sv_die "no such run: $SV_REVERT_RUN"
    runs=("$SV_BACKUP_ROOT/$SV_REVERT_RUN")
  else
    # Newest first, so the oldest backup is written last and the file ends up
    # as it was before securevps.sh ever touched it.
    # find exits non-zero when the directory does not exist, and pipefail
    # then carries that out of the assignment and set -e kills the run before
    # the message below is ever printed.
    local found=""
    if [[ -d "$SV_BACKUP_ROOT" ]]; then
      found="$(find "$SV_BACKUP_ROOT" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | sort -r || true)"
    fi
    [[ -n "$found" ]] || sv_die "nothing to revert, securevps.sh has not changed anything on this host"
    mapfile -t runs <<< "$found"
  fi

  sv_say "Reverting ${#runs[@]} run(s)${filter:+, modules: $filter}"
  local dir
  for dir in "${runs[@]}"; do
    sv_debug "run $(basename "$dir")"
    sv_revert_run "$dir" "$filter"
  done

  sv_say ""
  sv_ok "$SV_REVERT_COUNT file(s) restored"
  sv_note "Services still have the new config loaded. Restart the ones you care about, or reboot."
  local n
  for n in "${SV_NOTES[@]}"; do printf '  %s %s\n' "${C_YELLOW}*${C_RESET}" "$n"; done
  return 0
}

sv_cmd_confirm() {
  if [[ ! -f "$SV_STATE_DIR/ssh-rollback-pending" ]]; then
    sv_say "Nothing to confirm; no sshd rollback is armed."
    return 0
  fi
  sv_require_root
  systemctl stop securevps-ssh-rollback.timer >/dev/null 2>&1 || true
  systemctl reset-failed securevps-ssh-rollback.service >/dev/null 2>&1 || true
  rm -f "$SV_STATE_DIR/ssh-rollback-pending" "$SV_SSH_ROLLBACK"
  sv_ok "confirmed, the sshd rollback is cancelled"
  return 0
}

sv_cmd_help() {
  cat <<EOF
${C_BOLD}securevps.sh $SV_VERSION${C_RESET} - harden a Debian or Ubuntu VPS

${C_BOLD}USAGE${C_RESET}
  securevps.sh [command] [options]

${C_BOLD}COMMANDS${C_RESET}
  harden              run every step in the active profile (default)
  scan                report what is and is not applied, exit 1 on any failure
  revert [step...]    put back every file securevps.sh changed
  confirm             cancel the armed sshd rollback after testing a new session
  help                this text

${C_BOLD}HARDENING STEPS${C_RESET}
  Each one is also a command: securevps.sh ssh --port 2222

EOF
  local m
  for m in "${SV_MODULE_ORDER[@]}"; do
    printf '  %-12s %s\n' "$m" "${MODULE_DESC[$m]}"
  done

  cat <<EOF

${C_BOLD}PROFILES${C_RESET}
  core       ${SV_PROFILE_CORE[*]}
             the default. What every internet-facing VPS needs.
  minimal    ${SV_PROFILE_MINIMAL[*]}
             nothing here can break a running application.
  standard   ${SV_PROFILE_STANDARD[*]}
             core plus kernel, PAM, service, logging and mount hardening.

  Any step outside the profile is one command away:
  securevps.sh pam, securevps.sh mfa --enable, securevps.sh harden --profile standard.

${C_BOLD}COMMON OPTIONS${C_RESET}
  -n, --dry-run       show a diff of every change, write nothing
  -y, --yes           do not ask anything
  -v, --verbose       explain each decision
  -q, --quiet         errors only
      --json          machine-readable output, mainly for scan
      --profile P     core (default), minimal or standard
      --only a,b      run just these steps
      --skip a,b      run everything except these
      --no-backup     do not copy files before editing them, revert cannot undo the run
      --force         carry on past the lockout guards
      --run ID        revert only this run instead of all of them
  -h, --help          this text
  -V, --version       print the version

${C_BOLD}STEP OPTIONS${C_RESET}
  Every setting below is a flag. Inside a single-step run the prefix is
  optional, so these are the same thing:

      securevps.sh harden --ssh-port 2222
      securevps.sh ssh --port 2222

  Booleans take --flag to turn on and --no-flag to turn off.

EOF
  local key last_module="" module
  for key in "${OPT_ORDER[@]}"; do
    module="${key%%.*}"
    [[ "$module" == core ]] && continue
    if [[ "$module" != "$last_module" ]]; then
      printf '\n  %s%s%s\n' "$C_BOLD" "$module" "$C_RESET"
      last_module="$module"
    fi
    printf '    --%-28s %s%s\n' "${key%%.*}-${key#*.}" "${OPT_HELP[$key]}" \
      "$( [[ -n "${CFG[$key]}" ]] && printf ' [%s]' "${CFG[$key]}" )"
  done

  cat <<EOF

${C_BOLD}EXAMPLES${C_RESET}
  securevps.sh --dry-run                 see what a default run would change
  securevps.sh harden                    apply the core profile
  securevps.sh harden --profile standard every step that is on by default
  securevps.sh harden --ssh-port 2222 --firewall-allow 80,443
  securevps.sh ssh --tcp-forwarding      re-enable tunnels for an admin UI
  securevps.sh docker --allow-published 80,443
  securevps.sh scan --json | jq .summary
  securevps.sh revert ssh                undo only the sshd changes

Full documentation: https://github.com/MilzInformatik/securevps.sh
EOF
}

sv_main() {
  # --run is revert-only and has no CFG entry.
  local -a args=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --run) SV_REVERT_RUN="${2-}"; shift 2 ;;
      --run=*) SV_REVERT_RUN="${1#*=}"; shift ;;
      *) args+=("$1"); shift ;;
    esac
  done

  sv_parse_args ${args[@]+"${args[@]}"}

  case "$SV_CMD" in
    help|--help) sv_cmd_help; exit 0 ;;
  esac

  sv_detect_system

  case "$SV_CMD" in
    harden) sv_cmd_harden ;;
    scan) sv_cmd_scan ;;
    revert) sv_cmd_revert ;;
    confirm) sv_cmd_confirm ;;
    *) sv_cmd_module "$SV_CMD" ;;
  esac
}

sv_main "$@"
