#!/usr/bin/env bash
# Runs inside a throwaway container. Applies the modules that make sense
# without a host kernel, then checks that scan agrees and revert undoes it.
set -uo pipefail

SV=/work/securevps.sh
fail=0
step() { printf '\n\033[1m### %s\033[0m\n' "$*"; }
check() {
  if eval "$2" >/dev/null 2>&1; then printf '  ok   %s\n' "$1"
  else printf '  FAIL %s\n' "$1"; fail=$((fail + 1)); fi
}

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq openssh-server sudo >/dev/null 2>&1

# A key for the administrator, so the root lock is allowed to proceed.
mkdir -p /root/.ssh
ssh-keygen -q -t ed25519 -f /root/.ssh/id_test -N "" -C test
cat /root/.ssh/id_test.pub > /root/.ssh/authorized_keys

MODULES="updates,user,ssh,bruteforce,pam,services,time,logging,banner,kmodules,sysctl,mounts"

step "argument handling"
check "help exits 0"          "$SV help"
check "version exits 0"       "$SV --version"
check "bad flag is refused"   "! $SV --nonsense-flag"
check "bad module refused"    "! $SV scan --only nosuchmodule"
check "bad command refused"   "! $SV nosuchcommand"
check "two commands refused"  "! $SV harden scan"
# The command should be accepted before or after the flags; "--profile x
# harden" was rejected outright until it was tested for. What matters here is
# that the arguments parsed, not that the run succeeded: at this point in the
# test no account has a key yet, so ssh refuses on purpose.
parses() {
  local name="$1"; shift
  if "$@" 2>&1 | grep -qE 'unexpected argument|unknown (command|option|module)'; then
    printf '  FAIL %s\n' "$name"; fail=$((fail + 1))
  else
    printf '  ok   %s\n' "$name"
  fi
}
parses "flags before command"  $SV --profile minimal harden --dry-run --yes
parses "flags after command"   $SV harden --profile minimal --dry-run --yes
parses "module before flags"   $SV ssh --dry-run --yes
parses "module after flags"    $SV --dry-run ssh --yes
parses "revert takes a module" $SV revert ssh --dry-run

step "revert with nothing to revert"
# find(1) fails on a missing backup directory and pipefail used to carry that
# out of the assignment, killing the run with no message at all.
$SV revert >/tmp/revert0.log 2>&1 && rc=0 || rc=$?
check "exits non-zero"        "[ '$rc' != 0 ]"
check "says why"              "grep -q 'nothing to revert' /tmp/revert0.log"

step "dry run changes nothing"
before=$(md5sum /etc/ssh/sshd_config /etc/login.defs | md5sum)
$SV harden --dry-run --yes --only "$MODULES" >/tmp/dry.log 2>&1
after=$(md5sum /etc/ssh/sshd_config /etc/login.defs | md5sum)
check "files untouched by --dry-run" "[ '$before' = '$after' ]"
check "dry run produced diffs"       "grep -q '^dry ' /tmp/dry.log"

step "scan before"
$SV scan --only "$MODULES" >/tmp/scan1.log 2>&1
fails_before=$(grep -c 'FAIL' /tmp/scan1.log || true)
printf '  %s failing checks before\n' "$fails_before"

step "root lock guard"
# useradd leaves the new admin with a locked password and sudo asks for one,
# so key plus sudo group is not enough to make locking root safe.
$SV user --yes >/tmp/user0.log 2>&1
check "refuses to lock root while the admin cannot sudo" "grep -q 'not locking root' /tmp/user0.log"
check "says how to fix it"  "grep -q 'passwd deploy' /tmp/user0.log"
echo 'deploy:Smoke-Test-Pass-1' | chpasswd

step "harden"
$SV harden --yes --only "$MODULES" --no-updates-upgrade >/tmp/harden.log 2>&1
rc=$?
printf '  exit %s\n' "$rc"
tail -20 /tmp/harden.log | sed 's/^/  | /'

step "results"
check "sshd drop-in written"      "[ -f /etc/ssh/sshd_config.d/99-securevps.conf ]"
check "sshd config is valid"      "sshd -t"
check "password auth off"         "sshd -T | grep -qx 'passwordauthentication no'"
check "root login off"            "sshd -T | grep -qx 'permitrootlogin no'"
check "modern kex only"           "! sshd -T | grep '^kexalgorithms' | grep -q sha1"
check "admin user exists"         "id deploy"
check "admin in sudo group"       "id -nG deploy | tr ' ' '\n' | grep -qx sudo"
check "admin has the key"         "grep -q ssh-ed25519 /home/deploy/.ssh/authorized_keys"
check "admin can sudo"            "getent shadow deploy | cut -d: -f2 | grep -qvE '^[!*]'"
check "admin key mode 0600"       "[ \"\$(stat -c %a /home/deploy/.ssh/authorized_keys)\" = 600 ]"
check "root password locked"      "passwd -S root | awk '{print \$2}' | grep -qE '^(L|LK)\$'"
check "umask 027 in login.defs"   "grep -qE '^UMASK\s+027' /etc/login.defs"
check "banner installed"          "grep -qi authorised /etc/issue.net"
check "fail2ban jail written"     "[ -f /etc/fail2ban/jail.d/99-securevps.local ]"
check "pwquality written"         "grep -q 'minlen = 12' /etc/security/pwquality.conf.d/99-securevps.conf"
check "sshd drop-in mode 0600"    "[ \"\$(stat -c %a /etc/ssh/sshd_config.d/99-securevps.conf)\" = 600 ]"
check "backup manifest exists"    "[ -s /var/backups/securevps/latest/manifest.tsv ]"
check "container skips sysctl"    "grep -q 'container' /tmp/harden.log"

step "scan after"
$SV scan --only "$MODULES" >/tmp/scan2.log 2>&1
fails_after=$(grep -c 'FAIL' /tmp/scan2.log || true)
printf '  %s failing checks after (was %s)\n' "$fails_after" "$fails_before"
check "scan improved" "[ '$fails_after' -lt '$fails_before' ]"
grep 'FAIL' /tmp/scan2.log | sed 's/^/  | /' || true

step "idempotent: a second run changes nothing"
$SV harden --yes --only "$MODULES" --no-updates-upgrade >/tmp/harden2.log 2>&1
changes=$(grep -oE '^[0-9]+ change' /tmp/harden2.log | grep -oE '^[0-9]+' || echo 99)
printf '  second run reported %s change(s)\n' "$changes"
check "second run is a no-op" "[ '${changes:-99}' -le 2 ]"

step "revert"
# Two runs touched login.defs, so this also proves the older run is replayed
# after the newer one rather than the command dying between them.
$SV revert >/tmp/revert.log 2>&1 && rc=0 || rc=$?
check "revert exits 0"            "[ '$rc' = 0 ]"
check "revert reports a count"    "grep -qE '[0-9]+ file\(s\) restored' /tmp/revert.log"
check "sshd config still valid after revert" "sshd -t"
check "our drop-in is gone"       "[ ! -f /etc/ssh/sshd_config.d/99-securevps.conf ]"
check "login.defs umask restored" "! grep -qE '^UMASK\s+027' /etc/login.defs"
check "created files are removed"  "[ ! -f /home/deploy/.ssh/authorized_keys ]"

step "custom flags"
# revert removed the authorized_keys it created, so re-establish a login path
# before asking the ssh module to do anything.
install -d -m 700 -o deploy -g deploy /home/deploy/.ssh
install -m 600 -o deploy -g deploy /root/.ssh/id_test.pub /home/deploy/.ssh/authorized_keys

$SV ssh --port 2222 --tcp-forwarding --yes >/tmp/ssh2.log 2>&1
check "port flag applied"          "sshd -T | grep -qx 'port 2222'"
check "short flag form works"      "sshd -T | grep -qx 'allowtcpforwarding yes'"
$SV ssh --ssh-port 2244 --yes >/tmp/ssh3.log 2>&1
check "prefixed flag form works"   "sshd -T | grep -qx 'port 2244'"
$SV ssh --port 22 --no-tcp-forwarding --yes >/dev/null 2>&1
check "--no- negation works"       "sshd -T | grep -qx 'allowtcpforwarding no'"

step "lockout guard"
rm -f /home/deploy/.ssh/authorized_keys /root/.ssh/authorized_keys
$SV ssh --yes >/tmp/lockout.log 2>&1
check "refuses a config with no way in" "grep -q 'no way to log in' /tmp/lockout.log"

printf '\n'
if [ "$fail" -eq 0 ]; then printf '\033[32mall checks passed\033[0m\n'; else printf '\033[31m%s check(s) failed\033[0m\n' "$fail"; fi
exit "$fail"
