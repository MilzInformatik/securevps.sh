# Design

## Command surface

```
securevps.sh [global flags] <command> [command flags]
```

Commands map one-to-one onto the modules in the catalog, plus three that do not harden
anything:

```
securevps.sh harden                 # run the modules in the active profile
securevps.sh scan                   # read-only report, non-zero exit on drift
securevps.sh revert [module...]     # restore the backups a run took
```

Any module runs alone:

```
securevps.sh ssh --port 2222 --allow-users deploy,alice
securevps.sh firewall --allow 80,443 --allow-from 10.0.0.0/8:5432
securevps.sh docker --no-icc
```

## Global flags

| Flag | Effect |
|---|---|
| `--dry-run` | print every change as a diff, touch nothing |
| `--yes` | no prompts, for cloud-init and CI |
| `--profile core\|minimal\|standard` | which steps `harden` runs |
| `--only <a,b>` / `--skip <a,b>` | module selection for `harden` |
| `--no-backup` | skip config backups, off by default |
| `--force` | carry on past the lockout guards |
| `--run ID` | `revert` one run instead of all of them |
| `--json` | machine-readable output, mainly for `scan` |
| `--quiet` / `--verbose` | log level |

Every module runs on its own with the same global flags, and `revert <module>`
undoes just that module's files.

## Profiles

`core` is the default: updates, user, firewall, ssh, docker, bruteforce. These
are the six steps every internet-facing VPS needs, and the six whose effects a
reader can hold in their head. When one of them breaks something, the cause
is obvious: a closed port, a key-only sshd, a Docker chain rule.

`minimal` is core without the two steps that touch accounts and Docker, plus
sysctl, time and banner. Nothing in it can break an application.

`standard` is core plus sysctl, kmodules, pam, services, time, logging,
apparmor, banner and mounts. Each of those is worth having, and each is the
kind of change that is hard to trace back when it does bite (a PAM lockout, a
blacklisted module, an AppArmor denial). So they are opt-in, one command
away, and the README describes each in a paragraph rather than a page.

There is no `paranoid` profile. An earlier draft had one, and most of what it
turned on was either actively harmful on a container host (noexec `/tmp`, no
container-to-container traffic), noisy enough to fill a small disk (the CIS
audit ruleset), or meaningless on a VPS (blacklisting usb-storage, which is
why that flag and the firewire one are gone). Everything else it did is still
one flag away, which is the better place for a setting that breaks things.

## Behaviour rules

Idempotent. Running twice changes nothing the second time, and `scan` after `harden` is clean.

Reversible. Before editing a file the module copies it to
`/var/backups/securevps/<timestamp>/` and records the change in a manifest. `revert` replays
the manifest backwards.

Additive. Config goes into drop-in directories (`/etc/ssh/sshd_config.d`, `/etc/sysctl.d`,
`/etc/fail2ban/jail.d`) with a `99-securevps` prefix. The distro's files stay untouched, so a
distro upgrade does not fight the script.

Validated. Anything with a syntax checker gets checked before the service reloads: `sshd -t`,
`nft -c`, `fail2ban-client -t`, `visudo -c`, `apparmor_parser -Q`. A failed check restores the
backup and aborts the module rather than the whole run.

Lockout-safe. The SSH module refuses a config no account could log in through, validates
with `sshd -t` before reloading, and arms a systemd timer that restores the previous config
unless `securevps.sh confirm` runs from a second session. `--yes` skips the prompt but keeps
the timer. The user module refuses to lock root until some non-root account has a key, sudo
membership, and either a password or a NOPASSWD rule.

Loud about what it cannot know. If Docker publishes a port to `0.0.0.0`, if a non-root user is
in the `docker` group, if the box is a router, the script reports and does not silently
"fix" it.

## Repository layout

```
securevps.sh              # the whole thing, one file
README.md                 # the guide, and one section per hardening practice
docs/design.md            # this file
tests/
  readme-commands.sh      # every command in the README must parse
  integration/run.sh      # builds a throwaway rootfs and runs the suite in it
  integration/smoke.sh    # the suite itself
```

One hand-written file, no build step. That is a deliberate trade: the file is
long, and in exchange there is nothing to get out of sync, nothing to install,
and the thing you download is the thing you read. For a script whose job is to
edit sshd on a machine you cannot afford to lose, being auditable in one pass
is worth more than being tidy to work on.

The file reads top to bottom in three parts: the helpers every step is built
from, the settings table, then the steps themselves. Each step is two
functions, with a block above them saying what it changes and why:

```
<m>_apply    make the changes
<m>_scan     report on them, one sv_check per finding
```

Its one-line summary lives in the `MODULE_DESC` table at the top. Adding a step
means writing those two functions, adding its options with `defopt`, and adding
its name to `MODULE_DESC`, `SV_MODULE_ORDER` and whichever profile should run
it.

Install is a download:

```
curl -fsSLO https://.../securevps.sh
less securevps.sh
sudo bash securevps.sh harden
```

Piping straight into bash is deliberately not documented. Downloading and
reading the thing before it edits sshd is a habit worth keeping in a security
tool.

## Testing

- `shellcheck` over every file, clean at its default severity.
- `tests/readme-commands.sh` parses every command the README tells people to
  run, so a renamed flag cannot quietly rot the documentation.
- `tests/integration/run.sh <suite>` builds a throwaway root filesystem with
  debootstrap, runs the modules in it, and checks: a dry run writes nothing,
  the applied state is what was asked for, `scan` agrees, a second run reports
  zero changes, `revert` puts everything back, all three flag forms work, the
  ssh guard refuses a configuration with no way in, and the user guard refuses
  to lock root while the admin cannot sudo.

A chroot has no systemd and no host kernel, so the modules that need those
report themselves as skipped rather than being exercised. `firewall`, `sysctl`,
`kmodules`, `mounts` and `apparmor` therefore need a real VM to test honestly,
and that is the gap in the current suite.
