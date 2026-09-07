#!/usr/bin/env bash
#
# Runs the smoke test against a throwaway Debian or Ubuntu root filesystem.
#
#   sudo tests/integration/run.sh                 # Ubuntu 24.04
#   sudo tests/integration/run.sh bookworm        # Debian 12
#
# Docker would be the obvious way to do this, but a chroot needs no daemon and
# no image registry, which matters in locked-down build environments. The
# trade-off is no systemd, so the modules that need a host kernel report
# themselves as skipped rather than being exercised here.
set -euo pipefail

SUITE="${1:-noble}"
case "$SUITE" in
  noble|jammy) MIRROR="http://archive.ubuntu.com/ubuntu/" ;;
  bookworm|trixie) MIRROR="http://deb.debian.org/debian/" ;;
  *) echo "unknown suite: $SUITE" >&2; exit 2 ;;
esac

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CACHE="${SECUREVPS_TEST_CACHE:-/tmp/securevps-test}"
BASE="$CACHE/$SUITE.tar.gz"
ROOT="$CACHE/root-$SUITE-$$"

command -v debootstrap >/dev/null || { echo "install debootstrap first" >&2; exit 2; }
[[ "$(id -u)" -eq 0 ]] || { echo "run as root" >&2; exit 2; }

# Removing the tree while a bind mount is still live deletes the host's real
# /dev. A lazy unmount returns before the mount is actually gone, so this
# unmounts properly, verifies with mountpoint, and refuses to delete anything
# if even one is left standing.
cleanup() {
  local m still=0
  for m in proc/sys/fs/binfmt_misc dev/pts dev/shm dev sys proc; do
    [[ -d "$ROOT/$m" ]] || continue
    mountpoint -q "$ROOT/$m" || continue
    umount "$ROOT/$m" 2>/dev/null || umount -l "$ROOT/$m" 2>/dev/null || true
  done
  for m in proc dev sys; do
    mountpoint -q "$ROOT/$m" 2>/dev/null && { echo "still mounted: $ROOT/$m" >&2; still=1; }
  done
  if [[ $still -eq 1 ]]; then
    echo "refusing to remove $ROOT while something is still mounted under it" >&2
    echo "unmount it by hand, then: rm -rf $ROOT" >&2
    return 0
  fi
  rm -rf "$ROOT" 2>/dev/null || true
}
trap cleanup EXIT

command -v mountpoint >/dev/null || { echo "mountpoint(1) is required" >&2; exit 2; }

if [[ ! -f "$BASE" ]]; then
  echo "building the $SUITE base image, this happens once"
  mkdir -p "$CACHE/build-$SUITE"
  debootstrap --variant=minbase \
    --include=systemd,sudo,ca-certificates,openssh-server \
    "$SUITE" "$CACHE/build-$SUITE" "$MIRROR" >/dev/null
  # A chroot has no host kernel, which is exactly what the container guard
  # in securevps.sh keys off.
  touch "$CACHE/build-$SUITE/.dockerenv"
  chroot "$CACHE/build-$SUITE" apt-get update -qq >/dev/null 2>&1 || true
  tar -C "$CACHE/build-$SUITE" -czf "$BASE" .
  # Nothing is mounted under the build tree, but check before deleting anyway.
  if mountpoint -q "$CACHE/build-$SUITE/dev" 2>/dev/null; then
    echo "unexpected mount under the build tree, leaving it in place" >&2
  else
    rm -rf "$CACHE/build-$SUITE"
  fi
fi

mkdir -p "$ROOT"
tar -C "$ROOT" -xzf "$BASE"
mkdir -p "$ROOT/work" "$ROOT/proc" "$ROOT/sys" "$ROOT/dev"
cp "$REPO/securevps.sh" "$ROOT/work/"
mkdir -p "$ROOT/work/tests/integration"
cp "$REPO/tests/integration/smoke.sh" "$ROOT/work/tests/integration/"
mount --bind /proc "$ROOT/proc"
mount --bind /dev "$ROOT/dev"
mount --bind /sys "$ROOT/sys"

echo "== $SUITE =="
chroot "$ROOT" bash /work/tests/integration/smoke.sh
