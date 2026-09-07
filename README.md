# securevps.sh

Hardening for a fresh Debian or Ubuntu VPS: a script that does the work, and a
guide that explains what it did and why.

Twenty hardening steps behind one command. Each one runs on its own, takes
flags, is idempotent, and can be undone.

```sh
curl -fsSLO https://raw.githubusercontent.com/MilzInformatik/securevps.sh/main/securevps.sh
less securevps.sh                 # it is about to edit sshd, read it first
sudo bash securevps.sh --dry-run  # see every change as a diff
sudo bash securevps.sh harden     # apply
```

The dry run is not ceremony. It prints a unified diff of every file the script
would touch, so you can see the sshd config before it is installed rather than
after.

## What it does by default

```
sudo securevps.sh harden
```

- Installs pending security updates and turns on unattended security upgrades.
- Creates a `deploy` user with sudo, copies root's SSH key to it, and locks
  root's password once that account is proven to work.
- Locks sshd down: keys only, no root login, modern crypto, no forwarding.
- Turns on the firewall, default-deny inbound, with only SSH open.
- Stops published Docker container ports from bypassing that firewall.
- Installs fail2ban with the address you are connected from on the never-ban list.
- Sets 43 kernel parameters and blacklists 13 unused kernel modules.
- Password quality, lockout after five failures, yescrypt hashing.
- Disables services a VPS does not need, makes the journal persistent, turns on
  auditd, puts AppArmor profiles into enforce, installs a login banner.

It does not open ports 80 and 443, move SSH off port 22, disable IPv6, or mount
`/tmp` noexec. Those are one flag each. Nothing in the default profile should
break a working application.

## Doing one thing at a time

Every step is a subcommand with its own flags:

```sh
sudo securevps.sh ssh --port 2222 --allow-users deploy,alice
sudo securevps.sh firewall --allow 80,443 --allow-from 10.0.0.0/8:5432
sudo securevps.sh docker --allow-published 80,443
sudo securevps.sh bruteforce --maxretry 3 --bantime 24h
```

Inside a single-module run the prefix is optional, so `securevps.sh ssh --port`
and `securevps.sh harden --ssh-port` set the same thing. Booleans use `--flag`
and `--no-flag`. `securevps.sh help` lists all of them with their defaults.

Settings can also live in `/etc/securevps.conf`, which is the right answer when
you want the same box twice:

```ini
ssh.port = 2222
ssh.tcp-forwarding = true
firewall.allow = 80,443
user.name = admin
bruteforce.bantime = 24h
```

## Checking and undoing

```sh
sudo securevps.sh scan            # what is and is not applied
sudo securevps.sh scan --json     # same, for monitoring
sudo securevps.sh revert          # put every changed file back
sudo securevps.sh revert ssh      # or just one module's
```

`scan` exits non-zero when a check fails, so it works as a cron job or a
monitoring probe. Every file is copied to `/var/backups/securevps/<run>` before
it is edited, and `revert` replays those backups.

## Not getting locked out

Changing sshd over sshd is how people lose servers. The ssh module:

1. Refuses outright to install a config that no account could log in through.
   If password auth is going off and nobody has a key, it stops and says so.
2. Runs `sshd -t` before reloading, and restores the backup if it fails. It
   compares sshd's opinion before and after, so a problem that was already
   there is reported rather than blamed on your change.
3. Arms a systemd timer that puts the old config back in five minutes unless
   you confirm from a **second** session:

```sh
ssh -p 2222 deploy@server     # in a new terminal
sudo securevps.sh confirm     # cancels the rollback
```

Say nothing and the old config comes back by itself. Set
`--ssh-rollback-timeout 0` to turn that off once you trust it.

## Profiles

```sh
sudo securevps.sh harden --profile minimal
```

`minimal` is what I would run on any box without thinking, and cannot break an
application. `standard` is the default. `paranoid` adds noexec `/tmp`, AIDE, the
CIS audit ruleset and stricter kernel settings; it will break something, which is
why it has its own name.

## Documentation

- [Guide](docs/guide.md) covers a fresh VPS end to end, including the parts a
  script should not do for you.
- [Hardening catalog](docs/hardening-catalog.md) lists every control, its
  default, its flag, and how likely it is to break something.
- [Design](docs/design.md) covers the command surface and the rules the script
  follows.

## Requirements

Debian 11+ or Ubuntu 22.04+, root, and bash. Other distributions are refused
rather than half-supported.

## Tests

```sh
sudo apt-get install -y debootstrap shellcheck
shellcheck securevps.sh
sudo tests/integration/run.sh noble       # or bookworm
```

The integration test builds a throwaway root filesystem, applies the modules,
scans, runs again to prove nothing changes twice, reverts, and checks the
lockout guard actually refuses.
