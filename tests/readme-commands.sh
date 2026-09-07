#!/usr/bin/env bash
#
# Every "securevps.sh ..." line in the README must parse. A README full of
# flags that do not exist is worse than no README.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SV="$REPO/securevps.sh"
fail=0 checked=0

# Pull the commands out of the fenced sh blocks, joining continuations. Only
# lines where securevps.sh is the command count; "install securevps.sh /usr/
# local/sbin/" is not one.
mapfile -t cmds < <(
  # shellcheck disable=SC2016  # a sed program, not a shell expansion
  sed -n '/^```sh$/,/^```$/p' "$REPO/README.md" \
    | sed 's/[[:space:]]*#.*$//' \
    | awk '/\\$/ { sub(/\\$/,""); printf "%s", $0; next } { print }' \
    | grep -E '^(sudo )?(bash )?(\./|/usr/local/sbin/)?securevps\.sh[[:space:]]' \
    | sed -E 's/^[^[:space:]]*securevps\.sh[[:space:]]+//; s/^(sudo |bash )+[^[:space:]]*securevps\.sh[[:space:]]+//' \
    | sed -E 's/[[:space:]]+$//' \
    | grep -v '^$' | sort -u
)

for c in "${cmds[@]}"; do
  # Skip anything with a pipe or a command substitution.
  # shellcheck disable=SC2016  # a literal $( is exactly what this looks for
  [[ "$c" == *'|'* || "$c" == *'$('* || "$c" == *'`'* ]] && continue
  checked=$((checked + 1))
  # eval so that quoted arguments in the README survive as one word.
  eval "set -- $c"
  out="$($SV "$@" --dry-run 2>&1 </dev/null || true)"
  if grep -qE 'unknown (option|module|command|setting)|unexpected argument|needs a value' <<<"$out"; then
    printf '  FAIL securevps.sh %s\n       %s\n' "$c" \
      "$(grep -m1 -E 'unknown|unexpected|needs a value' <<<"$out")"
    fail=$((fail + 1))
  fi
done

printf '\n%d README commands checked, %d bad\n' "$checked" "$fail"
exit $((fail > 0))
