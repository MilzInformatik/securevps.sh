#!/usr/bin/env bash
#
# Every "securevps.sh ..." line in the README must parse. A README full of
# flags that do not exist is worse than no README.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SV="$REPO/securevps.sh"
fail=0 checked=0

# Pull the commands out of the fenced sh blocks, joining continuations.
mapfile -t cmds < <(
  # shellcheck disable=SC2016  # a sed program, not a shell expansion
  sed -n '/^```sh$/,/^```$/p' "$REPO/README.md" \
    | sed 's/[[:space:]]*#.*$//' \
    | awk '/\\$/ { sub(/\\$/,""); printf "%s", $0; next } { print }' \
    | grep -E '(^|[[:space:]])securevps\.sh[[:space:]]' \
    | sed -E 's/.*securevps\.sh[[:space:]]+//' \
    | sed -E 's/[[:space:]]+$//' \
    | grep -v '^$' | sort -u
)

for c in "${cmds[@]}"; do
  # Skip the download line and anything with a shell redirect.
  [[ "$c" == -o* || "$c" == *'|'* ]] && continue
  checked=$((checked + 1))
  # shellcheck disable=SC2086  # the README line is a deliberate word list
  out="$($SV $c --dry-run 2>&1 </dev/null || true)"
  if grep -qE 'unknown (option|module|command|setting)|unexpected argument|needs a value' <<<"$out"; then
    printf '  FAIL securevps.sh %s\n       %s\n' "$c" \
      "$(grep -m1 -E 'unknown|unexpected|needs a value' <<<"$out")"
    fail=$((fail + 1))
  fi
done

printf '\n%d README commands checked, %d bad\n' "$checked" "$fail"
exit $((fail > 0))
