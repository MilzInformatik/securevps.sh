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
securevps.sh docker --disable-icc
```

## Global flags

| Flag | Effect |
|---|---|
| `--dry-run` | print every change as a diff, touch nothing |
| `--yes` | no prompts, for cloud-init and CI |
| `--profile minimal\|standard\|paranoid` | which modules `harden` runs and how far each goes |
| `--config /etc/securevps.conf` | key=value file, flags on the command line win |
| `--only <a,b>` / `--skip <a,b>` | module selection for `harden` |
| `--no-backup` | skip config backups, off by default |
| `--json` | machine-readable output, mainly for `scan` |
| `--quiet` / `--verbose` | log level |

Every module also takes `--dry-run` and `--revert` on its own.

## Profiles

`minimal` is the set I would run on any box without thinking: updates, ssh, firewall,
bruteforce, sysctl, time, banner. Nothing in it can break an application.

`standard` is the default. It adds user, docker when Docker is present, pam, services,
logging, kmodules, apparmor.

`paranoid` adds mounts with `noexec`, integrity, the CIS audit ruleset, stricter sysctl, and
turns on the controls the other profiles leave off. It will break something. That is the point
of a separate name.

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

Lockout-safe. The SSH module opens a temporary sshd on a second port, applies the change,
waits for the operator to confirm a new session works, and rolls back on a timeout if nobody
confirms. `--yes` skips the wait but keeps the rollback timer.

Loud about what it cannot know. If Docker publishes a port to `0.0.0.0`, if a non-root user is
in the `docker` group, if the box is a router, the script reports and does not silently
"fix" it.

## Repository layout

```
securevps.sh              # the whole thing, one file
securevps.conf.example    # the settings people actually change
docs/
  guide.md                # the prose guide
  hardening-catalog.md    # every control, its default, its flag
  design.md               # this file
tests/
  integration/run.sh      # builds a throwaway rootfs and runs the suite in it
  integration/smoke.sh    # the suite itself
```

One hand-written file, no build step. That is a deliberate trade: the file is
long, and in exchange there is nothing to get out of sync, nothing to install,
and the thing you download is the thing you read. For a script whose job is to
edit sshd on a machine you cannot afford to lose, being auditable in one pass
is worth more than being tidy to work on.

Section banners divide it, and every module follows the same three-function
contract, so the size is navigable:

```
<m>_apply    make the changes
<m>_scan     report on them via sv_check
<m>_desc     one line for the help output
```

Adding a module means writing those three, adding its options with `defopt`,
and adding its name to `SV_MODULE_ORDER` and whichever profiles should run it.

Install is a download and a checksum:

```
curl -fsSLO https://.../securevps.sh
sha256sum -c securevps.sh.sha256
sudo bash securevps.sh harden
```

Piping straight into bash is documented but not the headline instruction.
Downloading, checking the hash, and reading the thing before it edits sshd is a
habit worth keeping in a security tool.

## Testing

- `shellcheck` over every file, clean at warning level.
- `tests/integration/run.sh <suite>` builds a throwaway root filesystem with
  debootstrap, runs the modules in it, and checks: a dry run writes nothing,
  the applied state is what was asked for, `scan` agrees, a second run reports
  zero changes, `revert` puts everything back, all three flag forms work, and
  the lockout guard refuses a configuration with no way in.

A chroot has no systemd and no host kernel, so the modules that need those
report themselves as skipped rather than being exercised. `firewall`, `sysctl`,
`kmodules`, `mounts` and `apparmor` therefore need a real VM to test honestly,
and that is the gap in the current suite.
