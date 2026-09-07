# securevps.sh

A hardening script and a guide for Linux VPSes.

Two things live here. The guide explains what to do to a fresh VPS and why each step matters.
The script does it for you, one step at a time or all at once, with flags for the parts you
want to decide yourself.

Status: designing. Nothing is implemented yet.

- [Hardening catalog](docs/hardening-catalog.md) lists every control, its default, and the flag
  that changes it.
- [Design](docs/design.md) covers the command surface, profiles, and the rules the script
  follows.

## The shape of it

```
sudo ./securevps.sh harden                          # safe defaults
sudo ./securevps.sh ssh --port 2222 --no-safety-net # one step, tuned
sudo ./securevps.sh scan                            # read-only report
sudo ./securevps.sh revert ssh                      # undo it
```
