# securevps.sh

Hardening for a Debian or Ubuntu VPS. One Bash file, twenty steps, each one
runnable on its own with flags, idempotent, and reversible.

```sh
curl -fsSLO https://raw.githubusercontent.com/MilzInformatik/securevps.sh/main/securevps.sh
less securevps.sh                 # it is about to edit sshd, read it first
sudo bash securevps.sh --dry-run  # every change as a diff, nothing written
sudo bash securevps.sh harden     # apply
```

The dry run is not ceremony. It prints a unified diff of every file the script
would touch, so you see the sshd config before it is installed rather than
after.

## Before you start

Two things need to be true before you touch sshd, and neither is in the
script's power to arrange.

**A console that does not go through SSH.** Hetzner, DigitalOcean, Vultr and
the rest all offer a web console. Find it and check it works now, not at the
moment you need it. Everything below is recoverable from a console and nothing
below is recoverable without one.

**An SSH keypair.** If you have not run `ssh-keygen -t ed25519` on the machine
you are sitting at, do it now. Every step assumes key-based login works.

```sh
ssh-copy-id root@your-server
ssh root@your-server        # must succeed without a password prompt
```

## How it works

```sh
sudo securevps.sh harden          # every step in the standard profile
sudo securevps.sh ssh --port 2222 # one step, tuned
sudo securevps.sh scan            # what is and is not applied
sudo securevps.sh revert ssh      # undo it
```

Every setting is a flag. Inside a single-step run the prefix is optional, so
`securevps.sh ssh --port 2222` and `securevps.sh harden --ssh-port 2222` do the
same thing. Booleans take `--flag` and `--no-flag`. `securevps.sh help` lists
all of them with their defaults.

Two profiles. `minimal` is what I would run on any box without thinking and
cannot break a running application: updates, ssh, firewall, bruteforce, sysctl,
time, banner. `standard` is the default and adds the rest. There is no third
profile, because anything outside these is one command away.

Every file is copied into `/var/backups/securevps/<run>` before it is edited,
and `revert` replays those backups. Config goes into drop-in directories with a
`99-securevps` prefix, so a distribution upgrade does not fight it. Running
twice changes nothing the second time.

## Not getting locked out

Changing sshd over sshd is how people lose servers. The ssh step:

1. Refuses outright to install a config that no account could log in through.
   If password auth is going off and nobody has a key, it stops and says so.
2. Runs `sshd -t` before reloading, and restores the backup if it fails. It
   compares sshd's opinion before and after, so a problem that was already
   there is reported rather than blamed on your change.
3. Arms a timer that puts the old config back in five minutes unless you
   confirm from a **second** session:

```sh
ssh -p 2222 deploy@server     # in a new terminal
sudo securevps.sh confirm     # cancels the rollback
```

Say nothing and the old config comes back by itself.

---

# Hardening practices

## Hardening practice 1: patch, and keep patching

* **What it does.** Installs pending updates, then enables `unattended-upgrades`
  restricted to the security pocket. Sets `needrestart` to restart patched
  services automatically. Automatic reboots stay off unless you ask.
* **Why it does it.** Most compromised servers were not cleverly attacked. They
  ran a version of something with a published advisory and nobody applied it.
  Restarting services matters as much as the patch: updating a library does
  nothing for processes that already mapped the old one.
* **Command to run.**

```sh
sudo securevps.sh updates
sudo securevps.sh updates --auto-reboot 04:00     # reboot itself when needed
sudo securevps.sh updates --scope all             # not just the security pocket
```

## Hardening practice 2: a user that is not root

* **What it does.** Creates a `deploy` account with sudo, copies root's
  authorized keys to it, sets `umask 027`, restricts `su` to the sudo group,
  and locks root's password. Key-based root login is unaffected.
* **Why it does it.** Working as root means every mistake is unlimited and the
  logs cannot tell you who made it. The root lock is guarded: it verifies some
  non-root account really has a key and sudo rights first, because a script
  that locks root on a box with no other way in has destroyed something rather
  than hardened it. One key per person, not one shared by the team, or the
  audit log is useless and nothing can be revoked when somebody leaves.
* **Command to run.**

```sh
sudo securevps.sh user --name deploy
sudo securevps.sh user --ssh-key ~/.ssh/id_ed25519.pub
sudo securevps.sh user --no-lock-root              # leave root's password alone
```

## Hardening practice 3: key-only SSH

* **What it does.** Password and keyboard-interactive auth off, root login off,
  modern KEX/ciphers/MACs only, `MaxAuthTries 3`, forwarding disabled, DH
  moduli under 3072 bits removed, and the OS version no longer advertised.
  Written to `/etc/ssh/sshd_config.d/99-securevps.conf`.
* **Why it does it.** Turning password authentication off is the single most
  valuable change on this page. Everything else here is worth less than that
  one line: it takes brute forcing, credential stuffing and every leaked
  password off the table at once.
* **Command to run.**

```sh
sudo securevps.sh ssh
sudo securevps.sh ssh --port 2222                  # quieter logs, not security
sudo securevps.sh ssh --tcp-forwarding             # needed for ssh -L tunnels
sudo securevps.sh ssh --allow-users deploy,alice
```

`--tcp-forwarding` is the default most likely to surprise you. It is off, which
breaks `ssh -L`. If you reach an admin UI bound to `127.0.0.1` through a
tunnel, turn it back on.

Moving off port 22 stops essentially all background scanning noise and stops
none of a targeted attack, which finds the port in seconds. Worth doing for the
quieter logs, not because it is security.

## Hardening practice 4: a default-deny firewall

* **What it does.** Deny inbound, allow outbound, SSH rate-limited. Uses ufw if
  present, nftables otherwise. Keeps both the current SSH port and the one you
  are moving to open, so changing the port in the same run cannot strand you.
* **Why it does it.** A service you forgot is listening is a service somebody
  else will find. Ports 80 and 443 are not opened unless you ask, because
  plenty of servers are not web servers and an open port should be a decision
  somebody typed.
* **Command to run.**

```sh
sudo securevps.sh firewall --allow 80,443
sudo securevps.sh firewall --allow-from 10.0.0.0/8:5432
sudo securevps.sh firewall --backend nftables
```

Configure your provider's firewall too, in their panel. It filters before a
packet reaches the OS, so it still works when the OS rules are wrong, and it is
the only reliable answer to the next practice.

## Hardening practice 5: stop Docker bypassing the firewall

* **What it does.** Puts a default `DROP` in the `DOCKER-USER` iptables chain
  with private ranges allowed, and installs a systemd unit that reapplies it
  after every Docker restart. Also sets `no-new-privileges`, log rotation and
  `live-restore` in `daemon.json`.
* **Why it does it.** Docker writes its own iptables rules and they are
  evaluated before ufw's. Run `docker run -d -p 5432:5432 postgres` on a server
  with `ufw deny 5432` in place and Postgres is reachable from the internet;
  `ufw status` shows the deny rule doing nothing. This is documented behaviour,
  not a bug, and a great many people believe their database is firewalled when
  it is answering the world. `DOCKER-USER` is consulted before Docker's own
  accept rules and Docker never rewrites it, so a drop there actually holds.
  Restarting the daemon flushes the chain, which is why the unit exists.
* **Command to run.**

```sh
sudo securevps.sh docker
sudo securevps.sh docker --allow-published 80,443  # expose these publicly
sudo securevps.sh docker --allow-from 203.0.113.0/24
```

Better still, bind containers to loopback and put a reverse proxy in front:

```yaml
ports:
  - "127.0.0.1:5432:5432"
```

The step also reports two things it will not fix for you: anyone in the
`docker` group can start a container that mounts the host filesystem, so that
group is root by another name; and a container with `/var/run/docker.sock`
mounted is root on the host.

## Hardening practice 6: ban repeated login failures

* **What it does.** fail2ban watching sshd in aggressive mode, five failures
  per ten minutes, banned for an hour, plus a `recidive` jail that bans repeat
  offenders for a week. The address you are connected from is never banned.
* **Why it does it.** With key-only auth already in place this mostly saves log
  volume rather than stopping a real attack, but log volume is worth saving.
  The never-ban list is not optional in my view: fail2ban banning the
  administrator during setup is a rite of passage nobody needs.
* **Command to run.**

```sh
sudo securevps.sh bruteforce
sudo securevps.sh bruteforce --maxretry 3 --bantime 24h
sudo securevps.sh bruteforce --ignore-ip 203.0.113.5
sudo securevps.sh bruteforce --engine crowdsec
```

## Hardening practice 7: kernel and network parameters

* **What it does.** Writes 43 settings to `/etc/sysctl.d/99-securevps.conf`:
  reverse-path filtering, no source routing, no ICMP redirects, SYN cookies,
  martian logging, plus `kptr_restrict`, `dmesg_restrict`, `kexec_load_disabled`
  and the link protections.
* **Why it does it.** These turn a local information leak into a dead end and
  drop spoofed traffic before anything else sees it. `ip_forward` and
  unprivileged user namespaces are left on when Docker is installed, because
  turning either off breaks container networking entirely.
* **Command to run.**

```sh
sudo securevps.sh sysctl
sudo securevps.sh sysctl --no-ipv6                 # fully disable IPv6
sudo securevps.sh sysctl --ptrace-scope 2          # breaks debuggers
```

## Hardening practice 8: blacklist unused kernel modules

* **What it does.** Blacklists 13 modules: rare filesystems (cramfs, freevxfs,
  jffs2, hfs, hfsplus, udf), rare network protocols (dccp, sctp, rds, tipc) and
  firewire.
* **Why it does it.** Drivers for filesystems and protocols no server touches
  are still attack surface, and several of these have a history of bugs
  reachable by mounting a crafted image. squashfs is deliberately not on the
  list, because snap packages will not mount without it.
* **Command to run.**

```sh
sudo securevps.sh kmodules
sudo securevps.sh kmodules --usb-storage           # also block USB storage
```

## Hardening practice 9: password policy and lockout

* **What it does.** Minimum 12 characters from 3 character classes, no reuse of
  the last 5, lockout for 15 minutes after 5 failures, yescrypt hashing, and
  password ageing in `/etc/login.defs`.
* **Why it does it.** This matters even with key-only SSH, because sudo, the
  provider console and every PAM-using service still take passwords. Key-only
  SSH does nothing for an attacker who is already on the box.
* **Command to run.**

```sh
sudo securevps.sh pam
sudo securevps.sh pam --min-length 16
sudo securevps.sh pam --tmout 900                  # idle shell timeout
```

## Hardening practice 10: stop what should not be listening

* **What it does.** Reports every listening socket with its owning process,
  then disables services a VPS rarely needs: rpcbind, avahi, cups, nfs, telnet,
  vsftpd, samba, snmpd and friends.
* **Why it does it.** The cheapest attack surface reduction there is. A service
  that is not running cannot be exploited, and most of these are installed by a
  dependency nobody chose.
* **Command to run.**

```sh
sudo securevps.sh services
sudo securevps.sh services --no-disable            # report, change nothing
sudo securevps.sh services --purge                 # uninstall rather than stop
sudo securevps.sh services --keep snmpd
```

## Hardening practice 11: a correct clock

* **What it does.** Installs chrony, sets the timezone to UTC, and verifies the
  clock is actually synchronised.
* **Why it does it.** Certificate validation and any attempt to line up two
  logs both fall apart on a drifting clock. This is not glamorous and it breaks
  incident response completely when it is wrong.
* **Command to run.**

```sh
sudo securevps.sh time
sudo securevps.sh time --timezone Europe/Zurich
```

## Hardening practice 12: logs that survive a reboot

* **What it does.** Persistent journal in `/var/log/journal` capped at 1G with
  a month of retention, plus auditd with a light ruleset covering identity
  changes, sudo use, module loading and time changes.
* **Why it does it.** Without this the journal lives in `/run` and is gone
  after a reboot, which is exactly when you want to read it. The audit ruleset
  stays light by default because the full CIS set is verbose enough to fill a
  small disk.
* **Command to run.**

```sh
sudo securevps.sh logging
sudo securevps.sh logging --audit-rules cis
sudo securevps.sh logging --remote-syslog logs.example.com:514
```

Ship logs off the host if you can. Logs on a compromised host are evidence
under the attacker's control.

## Hardening practice 13: AppArmor in enforce mode

* **What it does.** Installs AppArmor, enables it, and moves every profile from
  complain mode into enforce.
* **Why it does it.** A profile in complain mode logs what it would have
  blocked and blocks nothing, which is worth roughly nothing on its own. Ubuntu
  ships profiles for several network-facing services already; they just need to
  be enforcing.
* **Command to run.**

```sh
sudo securevps.sh apparmor
```

If an application starts failing on file access afterwards, check
`journalctl -k | grep apparmor`.

## Hardening practice 14: a login banner that says nothing useful

* **What it does.** Replaces `/etc/issue`, `/etc/issue.net` and the motd with a
  warning banner, and stops sshd advertising its Debian version string.
* **Why it does it.** The stock `/etc/issue.net` prints your distribution and
  kernel version to anyone who opens a connection, before they authenticate.
  That is free reconnaissance. The legal wording is also what makes
  unauthorised access prosecutable in several jurisdictions.
* **Command to run.**

```sh
sudo securevps.sh banner
sudo securevps.sh banner --file /etc/my-banner.txt
```

## Hardening practice 15: mount options on scratch directories

* **What it does.** `nodev,nosuid,noexec` on `/dev/shm` by default. `/tmp` and
  `/var/tmp` are available behind flags.
* **Why it does it.** `/dev/shm` is pure win: nothing legitimate executes or
  creates device nodes there, and it is a favourite staging area for exploits
  that need somewhere writable. `/tmp` and `/var/tmp` are opt-in because
  package installers, language toolchains and container image builds all
  extract to them and then run what they extracted, so `noexec` there breaks
  real things.
* **Command to run.**

```sh
sudo securevps.sh mounts
sudo securevps.sh mounts --var-tmp --tmp
sudo securevps.sh mounts --noexec-tmp              # expect breakage
```

Mount options take effect at boot, so reboot when convenient and run
`securevps.sh scan` afterwards.

## Hardening practice 16: take SSH off the public internet

* **What it does.** Installs WireGuard or Tailscale, and optionally binds sshd
  to the VPN address only, so the public SSH port stops answering.
* **Why it does it.** The strongest single change available. A port that never
  appears in a public scan does not get brute forced, does not appear in a mass
  exploitation campaign for the next OpenSSH CVE, and does not fill your logs.
* **Command to run.**

```sh
sudo securevps.sh vpn --provider tailscale --tailscale-authkey tskey-...
sudo securevps.sh vpn --ssh-vpn-only
```

Keep the provider console available, because the VPN is now a dependency of
your access. The step refuses to bind sshd to an interface that has no address
yet.

## Hardening practice 17: a second factor on SSH

* **What it does.** Requires a TOTP code in addition to the SSH key, with a
  named account exempt so automated deploys keep working. Off by default.
* **Why it does it.** A key is a file, and files get copied off laptops. A
  second factor means a stolen key alone is not enough.
* **Command to run.**

```sh
sudo securevps.sh mfa --enable --exempt-user deploy
google-authenticator                               # once, as each user
```

Until each user has enrolled, `nullok` lets them in without a code. Remove it
once everyone has a secret.

## Hardening practice 18: know when someone logs in

* **What it does.** A PAM hook that sends mail or a webhook on every
  interactive SSH login. Off by default.
* **Why it does it.** Cheap, and often the first thing that tells you a key has
  been copied. You know your own login times; an unexpected one at 03:00 is a
  signal nothing else gives you that fast.
* **Command to run.**

```sh
sudo securevps.sh alerts --login-alert --email you@example.com
sudo securevps.sh alerts --login-alert --webhook https://hooks.example.com/x
```

## Hardening practice 19: file integrity monitoring

* **What it does.** Installs AIDE, builds a baseline database, and schedules a
  daily check. Off by default.
* **Why it does it.** Tells you what changed on disk, which is the question you
  cannot otherwise answer after a suspected compromise. Off by default because
  the first run takes minutes and the daily mail is noise unless somebody reads
  it. Worth knowing: the database sits on the host it is checking, so an
  attacker with root rewrites both. Copy it somewhere else for it to mean
  anything.
* **Command to run.**

```sh
sudo securevps.sh integrity --enable
sudo securevps.sh integrity --enable --schedule weekly
```

## Hardening practice 20: backups you have actually restored

* **What it does.** Installs restic, writes a config and a systemd timer
  pointed at a repository you supply, with a sensible retention policy. Off by
  default and it will not invent a destination.
* **Why it does it.** Every other practice on this page reduces the chance of a
  bad day. This is the one that decides how bad the day is. A backup you have
  never restored is a hypothesis.
* **Command to run.**

```sh
sudo securevps.sh backup --enable --repo s3:s3.amazonaws.com/my-bucket \
  --password-file /etc/securevps/restic-password
restic restore latest --target /tmp/restore-test   # then actually look at it
```

---

## What the script will not do

Some things do not belong in a script, and doing them badly is worse than not
doing them.

* **Provider firewall.** Configure it in the panel. It runs before the OS sees
  the packet and it is the reliable answer to Docker's iptables behaviour.
* **Snapshots, and one tested restore.** Restore one, look at what came back,
  then believe in it.
* **Reverse proxy and TLS.** Caddy, Traefik or nginx. TLS 1.2 minimum, HSTS,
  Let's Encrypt. No admin interface on a public port: bind it to `127.0.0.1`
  and reach it over the VPN or an SSH tunnel.
* **Secrets.** Not in shell history, not in image layers, `0600` on env files.
  A real secret store once more than one person needs them.
* **DNS and mail.** CAA records. SPF, DKIM and DMARC if the box sends mail.
* **Your application.** Database users with the rights they need and no more,
  dependency updates, the framework's own guidance. A locked-down OS does
  nothing for an SQL injection.

## Checking and undoing

```sh
sudo securevps.sh scan            # exits non-zero when a check fails
sudo securevps.sh scan --json     # for monitoring
sudo securevps.sh revert          # put every changed file back
sudo securevps.sh revert ssh      # or just one step's
```

`scan` works unattended:

```
0 6 * * * /usr/local/sbin/securevps.sh scan --quiet || mail -s "drift on $(hostname)" you@example.com
```

## Requirements

Debian 11+ or Ubuntu 22.04+, root, bash. Other distributions are refused rather
than half-supported.

## Tests

```sh
sudo apt-get install -y debootstrap shellcheck
shellcheck securevps.sh
sudo tests/integration/run.sh noble       # or jammy, bookworm
```

The suite builds a throwaway root filesystem, applies the steps, scans, runs
again to prove nothing changes twice, reverts, and checks the lockout guard
refuses. A chroot has no systemd or host kernel, so `firewall`, `sysctl`,
`kmodules`, `mounts` and `apparmor` report as skipped there rather than being
exercised; those five need a real VM.

[Design notes](docs/design.md) cover the internals.
