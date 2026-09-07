# securevps.sh

Hardening for a Debian or Ubuntu VPS. One Bash file. By default it does six
things: patches the system, creates an admin account, closes the firewall,
locks down SSH, stops Docker from bypassing the firewall, and bans brute
forcers. Every change is written to a file you can read, is backed up first,
and can be undone with one command.

> **Disclaimer.** This script rewrites sshd and the firewall on a machine
> you probably cannot afford to lose. No warranty. Read it before you run
> it, dry-run it, keep a provider console open, and test a second login
> before you close the first. If it locks you out, that is between you and
> your server.

```sh
curl -fsSLO https://raw.githubusercontent.com/MilzInformatik/securevps.sh/main/securevps.sh
less securevps.sh                 # it is about to edit sshd, read it first
sudo bash securevps.sh --dry-run  # every change as a diff, nothing written
sudo bash securevps.sh harden     # apply the six core steps
```

## Contents

- [Before you start](#before-you-start)
- [Setting up a new server](#setting-up-a-new-server)
- [The six core steps](#the-six-core-steps)
  1. [updates](#1-updates) - security patches, now and automatically
  2. [user](#2-user) - an admin account, root locked behind it
  3. [ssh](#3-ssh) - key-only login, with a rollback timer
  4. [firewall](#4-firewall) - deny everything you did not open
  5. [docker](#5-docker) - published container ports respect the firewall
  6. [bruteforce](#6-bruteforce) - fail2ban on sshd
- [Commands](#commands) - [harden](#harden), [scan](#scan), [revert](#revert), [confirm](#confirm), [help](#help)
- [Global flags](#global-flags)
- [How it keeps you out of trouble](#how-it-keeps-you-out-of-trouble)
- [When something breaks](#when-something-breaks)
- [Optional steps](#optional-steps) - [sysctl](#sysctl), [kmodules](#kmodules), [pam](#pam), [services](#services), [time](#time), [logging](#logging), [apparmor](#apparmor), [banner](#banner), [mounts](#mounts), [vpn](#vpn), [mfa](#mfa), [alerts](#alerts), [integrity](#integrity), [backup](#backup)
- [What the script will not do](#what-the-script-will-not-do)
- [Requirements and tests](#requirements-and-tests)

## Before you start

Two things must be true before you touch sshd. The script cannot arrange
either of them.

**A console that does not go through SSH.** Hetzner, DigitalOcean, Vultr and
the rest all offer a web console. Find it and check it works now. Everything
below is recoverable from a console and nothing below is recoverable without
one.

**An SSH keypair that already works.** The `ssh` step turns passwords off.
If key login does not work yet, the step refuses to run.

## Setting up a new server

This is the whole sequence for a fresh box. Replace the address and the
ports with yours.

**On your own machine.** Skip the first line if you already have a key.

```sh
ssh-keygen -t ed25519
ssh-copy-id root@203.0.113.10
ssh root@203.0.113.10             # must work without a password prompt
```

**On the server, as root.** Install the script on `PATH` so `confirm` works
from a second session.

```sh
curl -fsSLO https://raw.githubusercontent.com/MilzInformatik/securevps.sh/main/securevps.sh
less securevps.sh
install -m 0755 securevps.sh /usr/local/sbin/
securevps.sh --dry-run --ssh-port 2222 --firewall-allow 80,443
securevps.sh harden    --ssh-port 2222 --firewall-allow 80,443
```

Two moments need you at the keyboard. The `user` step asks you to set a
password for the new `deploy` account, because sudo will ask for it later.
The `ssh` step arms a five minute rollback timer and prints the exact
command to test with.

**In a second terminal, without closing the first.**

```sh
ssh -p 2222 deploy@203.0.113.10
sudo securevps.sh confirm         # cancels the rollback
```

**Back on the server.**

```sh
securevps.sh scan                 # every check should pass or skip
```

Then set the provider firewall in their panel and take a snapshot. Those two
are listed under [what the script will not do](#what-the-script-will-not-do).

Variations you may want:

```sh
securevps.sh harden --docker-allow-published 80,443       # a container serves the web
securevps.sh harden --ssh-tcp-forwarding                  # you reach an admin UI over ssh -L
securevps.sh harden --user-name alice                     # admin account named alice
securevps.sh harden --yes --ssh-rollback-timeout 0        # unattended, for cloud-init or CI
```

## The six core steps

`harden` runs exactly these six, in the order updates, user, firewall, ssh,
docker, bruteforce. Each section says what changes on disk, why, the flags
worth knowing, and how to undo it. Flags are shown in the short form used
with the step's own command; on `harden` add the step name as a prefix, so
`ssh --port 2222` becomes `harden --ssh-port 2222`. Run `securevps.sh help`
for every flag and its default.

### 1. updates

Installs pending updates, then makes it keep happening without you.

**What changes.**

- Runs `apt-get upgrade` and removes orphaned packages and old kernels.
- Installs `unattended-upgrades`, restricted to security updates (on Ubuntu
  also the ESM pockets), and turns on the daily apt timers.
- Installs `needrestart`, set to restart patched services automatically.
- Does not reboot on its own unless you ask.

**Files.** `/etc/apt/apt.conf.d/99securevps-unattended`,
`/etc/apt/apt.conf.d/99securevps-periodic`,
`/etc/needrestart/conf.d/99-securevps.conf`.

**Why.** Most compromised servers ran something with a published advisory
that nobody patched. Restarting services matters as much as the patch: a
running process keeps using the old library.

| Flag | Default | Effect |
|---|---|---|
| `--auto-reboot` | off | Reboot at `HH:MM` when a patch needs it. |
| `--scope` | `security` | `all` also installs non-security updates. Riskier on a box nobody watches. |
| `--upgrade` | `true` | `--no-upgrade` configures without upgrading right now. |

```sh
sudo securevps.sh updates
sudo securevps.sh updates --auto-reboot 04:00
```

**Undo.** `securevps.sh revert updates` removes the three files. The packages
stay installed; `apt-get purge unattended-upgrades needrestart` if you want
them gone. A pending kernel update needs a reboot; `scan` warns until then.

### 2. user

A non-root administrator, and root's password locked.

**What changes.**

- Creates the account (default name `deploy`) with a home directory, adds it
  to the `sudo` group, and copies root's authorized keys to it.
- Asks you to set its password on the terminal, because sudo will ask for one.
- Locks root's password, but only after checking that the new account has a
  key, is in `sudo`, and has a password or a `NOPASSWD` rule. Without that
  the step refuses, so you cannot lock yourself out of sudo.
- Sets `umask 027` for login shells and restricts `su` to the `sudo` group.

**Files.** `/home/<name>/.ssh/authorized_keys`,
`/etc/profile.d/99-securevps-umask.sh`, one line each in `/etc/login.defs`
and `/etc/pam.d/su`, `/etc/sudoers.d/90-securevps-<name>` with
`--sudo-nopasswd`.

**Why.** Working as root means every mistake is unlimited and the logs cannot
say who did it. One key per person, or nothing can be revoked when somebody
leaves.

| Flag | Default | Effect |
|---|---|---|
| `--name` | `deploy` | The account name. |
| `--ssh-key` | root's keys | A public key, or a path to one. |
| `--sudo-nopasswd` | `false` | sudo without a password. Skips the password prompt. |
| `--lock-root` | `true` | `--no-lock-root` leaves root's password alone. |

```sh
sudo securevps.sh user
sudo securevps.sh user --name alice --ssh-key ~/.ssh/alice.pub
sudo securevps.sh user --sudo-nopasswd                 # automation accounts
```

**Undo.** `securevps.sh revert user` restores the edited files. It does not
unlock root or delete the account: `passwd -u root`, then `deluser deploy` if
you want it gone.

**Watch out.** The password prompt only appears on a terminal without
`--yes`. Unattended runs must pass `--sudo-nopasswd`, or root stays unlocked
and `scan` warns until you run `passwd deploy`. After a full `harden`, root
can only log in on the provider console.

### 3. ssh

Key-only sshd, no root login, and a rollback timer in case the new config
locks you out.

**What changes.** One drop-in file that:

- Turns off password login, keyboard-interactive login, root login and
  empty passwords. Only members of the `sudo` group may log in.
- Turns off TCP, agent and X11 forwarding. This is the setting most likely to
  surprise you: `ssh -L` tunnels stop working unless you pass
  `--tcp-forwarding`.
- Limits login attempts to 3 and the login window to 30 seconds. Idle
  sessions are dropped after two missed keepalives (10 minutes).
- Restricts key exchange, ciphers and MACs to the modern set, and stops
  advertising the Debian version.

It also removes the DSA host key, generates an ed25519 key if missing,
regenerates a weak RSA key at 4096 bits, and trims weak Diffie-Hellman
groups from `/etc/ssh/moduli`. Then it validates with `sshd -t`, reloads,
and arms the rollback timer.

**Files.** `/etc/ssh/sshd_config.d/99-securevps.conf`. On Ubuntu with
socket-activated sshd and a non-default port, also
`/etc/systemd/system/ssh.socket.d/99-securevps.conf`.

The drop-in, trimmed:

```ini
Port 22
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AuthenticationMethods publickey
AllowGroups sudo
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
DebianBanner no
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,...
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,...
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,...
```

**Why.** Turning password authentication off is the single most valuable
line in the file. It takes brute forcing, credential stuffing and every
leaked password off the table at once.

| Flag | Default | Effect |
|---|---|---|
| `--port` | `22` | Port sshd listens on. |
| `--tcp-forwarding` | `false` | Allow `ssh -L` and `ssh -R` tunnels. |
| `--agent-forwarding` | `false` | Allow `ssh -A`. |
| `--allow-users` | | `AllowUsers` list, on top of the `sudo` group rule. |
| `--permit-root` | `no` | `prohibit-password` lets root in with a key. Also pass `--allow-groups ""`. |
| `--rollback-timeout` | `300` | Seconds until an unconfirmed change rolls back. `0` disables the timer. |

```sh
sudo securevps.sh ssh
sudo securevps.sh ssh --port 2222
sudo securevps.sh ssh --tcp-forwarding
sudo securevps.sh ssh --permit-root prohibit-password --allow-groups ""
sudo securevps.sh ssh --yes --rollback-timeout 0        # unattended, no timer
```

**The rollback flow.** After the reload the step prints the command to test
with. Open a second terminal, log in, and run `securevps.sh confirm` there.
Do nothing and the old config comes back on its own after five minutes, with
a line in the journal tagged `securevps`.

**Undo.** `securevps.sh revert ssh`, then `systemctl reload ssh`. `revert`
puts files back; it never restarts a service for you.

**Watch out.**

- **Changing the port alone locks you out.** The firewall only opens the new
  port when it runs in the same invocation. Use `harden --ssh-port 2222`,
  or run `firewall` first.
- **`--yes` skips the prompt, not the timer.** Unattended runs need
  `--rollback-timeout 0`, or something that runs `confirm`.
- Moving off port 22 quiets the logs. It does not stop a targeted attack.

### 4. firewall

Deny everything inbound except SSH and the ports you name.

**What changes.**

- Default policy: deny inbound, allow outbound, deny routed.
- SSH is allowed and rate-limited, on the current port and on the port it is
  about to move to, so changing the port in the same run cannot strand you.
- Extra ports only if you pass `--allow`. Ports 80 and 443 are not opened by
  default, because an open port should be a decision somebody typed.
- Uses ufw if installed, nftables otherwise. Rules are mirrored onto IPv6.

**Files.** ufw: its own rule store and `IPV6=` in `/etc/default/ufw`.
nftables: `/etc/nftables.conf`, validated with `nft -c` before it loads.

**Why.** A service you forgot is listening is a service somebody else will
find.

| Flag | Default | Effect |
|---|---|---|
| `--allow` | | Ports to open: `80,443,25/tcp,51820/udp`. TCP unless told otherwise. |
| `--allow-from` | | Source-restricted rules: `10.0.0.0/8:5432`. |
| `--backend` | `auto` | `ufw` or `nftables`. |
| `--enable` | `true` | `--no-enable` writes rules without activating them. |

```sh
sudo securevps.sh firewall --allow 80,443
sudo securevps.sh firewall --allow 80,443,51820/udp
sudo securevps.sh firewall --allow-from 10.0.0.0/8:5432
sudo securevps.sh firewall --dry-run                     # the ufw commands it would run
```

**Undo.** `securevps.sh revert firewall` restores the files it edited. The
running rules stay until you run `ufw reset` or
`systemctl disable --now nftables`.

**Watch out.** Set your provider's firewall as well. It filters before the
packet reaches the OS, so it holds even when the OS rules are wrong.

### 5. docker

Stop published container ports from bypassing the firewall. Skipped when
Docker is not installed.

**What changes.**

- Adds a default `DROP` at the end of the `DOCKER-USER` iptables chain.
  Established traffic, loopback, private ranges and anything you allow are
  accepted before it.
- Installs a systemd unit that reapplies those rules after every Docker
  restart, because a restart flushes the chain.
- Merges `no-new-privileges`, `live-restore` and log rotation (10 MB, 3
  files) into `daemon.json`, keeping whatever else is in there, and restarts
  the daemon. With `live-restore`, containers survive the restart.

**Files.** `/etc/docker/daemon.json`,
`/usr/local/sbin/securevps-docker-firewall`,
`/etc/systemd/system/securevps-docker-firewall.service`.

**Why.** Docker writes its own iptables rules and they run before ufw's. Run
`docker run -p 5432:5432 postgres` on a box with `ufw deny 5432` and
Postgres answers the internet anyway. `DOCKER-USER` is the one chain Docker
consults first and never rewrites, so a drop there holds.

| Flag | Default | Effect |
|---|---|---|
| `--allow-published` | | Container ports that should be public anyway: `80,443`. |
| `--allow-from` | | CIDRs allowed to reach every published port. |
| `--firewall-fix` | `true` | `--no-firewall-fix` leaves iptables alone. |
| `--daemon-config` | `true` | `--no-daemon-config` leaves `daemon.json` alone. |

```sh
sudo securevps.sh docker --allow-published 80,443       # the reverse proxy is public
sudo securevps.sh docker --allow-from 203.0.113.0/24    # the office can reach everything
```

Better still, bind containers to loopback and put a reverse proxy in front:

```yaml
services:
  db:
    image: postgres:16
    ports:
      - "127.0.0.1:5432:5432"
```

**Undo.** `securevps.sh revert docker` restores `daemon.json` and removes the
unit and script. Then `systemctl restart docker` to drop the chain rules.

**Watch out.** A published port that stops answering after this step is the
step working. Add it to `--allow-published` if it is meant to be public. The
step also reports, but does not fix, containers with `/var/run/docker.sock`
mounted and members of the `docker` group, both of which are root on the
host.

### 6. bruteforce

Ban addresses that keep failing to log in.

**What changes.**

- Installs fail2ban, watching sshd through the journal on every port sshd
  uses. Five failures in ten minutes earns a one hour ban. Three bans in a
  day earns a one week ban.
- Your own address and loopback go on the never-ban list.

**Files.** `/etc/fail2ban/jail.d/99-securevps.local`,
`/etc/fail2ban/jail.d/99-securevps-recidive.local`,
`/etc/fail2ban/fail2ban.d/99-securevps-log.conf`. Validated with
`fail2ban-client -t` before restart.

**Why.** With key-only login this mostly saves log volume rather than
stopping an attack, but log volume is worth saving.

| Flag | Default | Effect |
|---|---|---|
| `--ignore-ip` | | Addresses or CIDRs never to ban. Put your office or VPN here. |
| `--maxretry` | `5` | Failures before a ban. |
| `--bantime` | `1h` | How long a ban lasts. |
| `--engine` | `fail2ban` | `crowdsec` if you installed it, or `none`. |

```sh
sudo securevps.sh bruteforce
sudo securevps.sh bruteforce --ignore-ip 203.0.113.5,10.0.0.0/8
sudo securevps.sh bruteforce --maxretry 3 --bantime 24h
```

Useful afterwards:

```sh
sudo fail2ban-client status sshd
sudo fail2ban-client set sshd unbanip 198.51.100.7
```

**Undo.** `securevps.sh revert bruteforce` removes the jail files. Then
`systemctl disable --now fail2ban`, or `apt-get purge fail2ban`.

**Watch out.** The never-ban entry for your own address is read from the SSH
session. When you run the script from the provider console it is not set,
so pass `--ignore-ip` for anything you must never lock out. If you move the
SSH port later, rerun this step so the jail follows.

## Commands

### harden

Runs the six core steps. A step that fails is reported and the run carries
on. At the end you get a change count, the notes each step left for you, and
the `revert` command for this exact run.

```sh
sudo securevps.sh harden
sudo securevps.sh harden --ssh-port 2222 --firewall-allow 80,443
sudo securevps.sh harden --only firewall,ssh --ssh-port 2222
sudo securevps.sh harden --skip docker
sudo securevps.sh harden --dry-run --verbose
sudo securevps.sh harden --profile standard             # core plus every optional step
```

A step's own name runs just that step, with the short flag form:

```sh
sudo securevps.sh firewall --allow 80,443
```

### scan

Read-only. One line per check, marked `pass`, `FAIL`, `warn` or `skip`.
Exits 1 on any `FAIL`. Run as root, because some checks read `/etc/shadow`
and the iptables chains.

```sh
sudo securevps.sh scan
sudo securevps.sh scan --quiet                     # only what is wrong
sudo securevps.sh scan --json | jq .summary
```

`scan` judges the host against the flags you give it, so repeat any custom
setting: `scan --ssh-port 2222`. Optional steps are checked only with
`--profile standard` or their own enable flag.

Run it from cron to catch drift:

```text
0 6 * * * /usr/local/sbin/securevps.sh scan --quiet || mail -s "drift on $(hostname)" you@example.com
```

### revert

Every file the script edits is copied to `/var/backups/securevps/<run>/`
first. `revert` puts the copies back, newest run first, so a file ends up as
it was before securevps.sh ever touched it.

```sh
sudo securevps.sh revert                           # every run, every step
sudo securevps.sh revert ssh                       # only the sshd files
sudo securevps.sh revert --dry-run                 # what would be restored
ls /var/backups/securevps/                         # the run IDs
```

`revert` restores files. It does not restart services, so reload the ones
you care about or reboot. It also does not undo things done by running a
command, and it tells you which ones it skipped. From the core steps:

- **Root's password lock.** `passwd -u root`.
- **The admin account.** `deluser deploy` if you want it gone.
- **Live firewall rules.** `ufw reset`, or `systemctl disable --now nftables`.
- **Installed packages and running services.** Purge or restart them.

### confirm

Cancels the sshd rollback timer. Run it from the new session, because that
is the point: if the new session works, the config is good.

```sh
sudo securevps.sh confirm
```

### help

Prints every command, step, flag and default. It is generated from the same
table the parser uses, so it cannot go stale.

```sh
securevps.sh help
securevps.sh help | grep -A 20 '^  ssh$'          # one step's flags
```

## Global flags

| Flag | Short | Effect |
|---|---|---|
| `--dry-run` | `-n` | Print every change as a diff. Write nothing. |
| `--yes` | `-y` | Answer every prompt with yes. The sshd rollback timer still arms. |
| `--verbose` | `-v` | Explain each decision. |
| `--quiet` | `-q` | Errors only. |
| `--profile P` | | `core` (default), `minimal` or `standard`. See [optional steps](#optional-steps). |
| `--only a,b` | | Run just these steps. |
| `--skip a,b` | | Run the profile without these steps. |
| `--json` | | Machine-readable output, for `scan`. |
| `--no-backup` | | Do not copy files before editing them. `revert` cannot undo such a run. |
| `--force` | | Carry on past the two lockout guards. Do not. |

Flags go before or after the command, `--flag=value` works, and every
boolean has a `--no-` form. Lists are comma separated with no spaces. Set
`NO_COLOR=1` to turn colour off.

## How it keeps you out of trouble

**Backups.** Every file is copied to `/var/backups/securevps/<run>/` before
it is edited. `latest` points at the newest run.

**Drop-ins, not edits.** Config goes into `/etc/ssh/sshd_config.d`,
`/etc/fail2ban/jail.d` and the like, as a file named `99-securevps` with a
header saying it is managed. The distribution's own files stay untouched, so
an upgrade does not fight the script. To find everything the script wrote:

```sh
grep -rl securevps /etc
```

**Validation before reload.** `sshd -t`, `nft -c`, `fail2ban-client -t`,
`visudo -c` and a JSON parse of `daemon.json` all run before the matching
service reloads. A failed check restores the backup and marks the step
failed.

**Idempotent.** Running twice changes nothing the second time.

**Lockout guards.** Three things stand between you and a locked server:

1. The `ssh` step refuses a config no account could log in through.
2. The `user` step refuses to lock root until some non-root account has a
   key, sudo, and a way to answer sudo's password prompt.
3. After a successful `sshd -t`, the `ssh` step arms a timer that puts the
   old config back in five minutes unless you `confirm` from a second
   session.

`--force` skips the first two. It is the wrong answer to a guard you do not
understand.

## When something breaks

Every symptom the six core steps can cause, and the cause.

| Symptom | Cause | Fix |
|---|---|---|
| SSH: `Permission denied (publickey)` | Password login is off and the account has no key, or is not in `sudo`. | Log in on the provider console. Add the key to `~/.ssh/authorized_keys`, or `securevps.sh revert ssh` and `systemctl reload ssh`. |
| SSH: connection refused or times out | Port changed without the firewall, or the provider firewall blocks it. | Console. `ufw status`, then `securevps.sh harden --only firewall,ssh --ssh-port <port>`. |
| SSH: worked, then stopped after 5 minutes | The rollback timer fired because nobody ran `confirm`. | Reconnect on the old port, rerun the `ssh` step, `confirm` from the second session. |
| SSH: `ssh -L` tunnel says `administratively prohibited` | Forwarding is off. | `securevps.sh ssh --tcp-forwarding`. |
| SSH: `Connection refused` after several typos | fail2ban banned you. | From another address: `fail2ban-client set sshd unbanip <ip>`. Then `--ignore-ip`. |
| `sudo` asks for a password you never set | The `user` step ran with `--yes` and no `--sudo-nopasswd`. | On the console: `passwd deploy`. |
| Root login on the console fails | Root's password is locked. Root has no password now; use the admin account. | `passwd -u root` if you need it back. |
| A published Docker port stopped answering | The `docker` step is working. | `securevps.sh docker --allow-published <port>`. |
| A web app is unreachable | Port not opened. | `securevps.sh firewall --allow 80,443`. |
| A service still runs the old library after an update | Nothing wrong. `needrestart` restarts it; kernel updates need a reboot. | `reboot` when convenient. |

For anything else, `securevps.sh scan --verbose` names the exact setting
that does not match, and `securevps.sh revert <step>` puts the files back.

## Optional steps

Fourteen more steps exist. None of them is in the default profile, because
each one either needs a decision from you, or can break an application in a
way that is hard to trace back. Run one with its name, or run them all with
`harden --profile standard`. Each entry says what changes, what it can
break, and how to undo it.

```sh
sudo securevps.sh pam                           # one optional step
sudo securevps.sh harden --profile standard     # core plus the first nine below
sudo securevps.sh harden --profile minimal      # updates ssh firewall bruteforce sysctl time banner
```

`--profile standard` adds sysctl, kmodules, pam, services, time, logging,
apparmor, banner and mounts. The last five (vpn, mfa, alerts, integrity,
backup) are off until you pass their enable flag, in any profile.

### sysctl

Writes about 40 kernel settings to `/etc/sysctl.d/99-securevps.conf` and
applies them live. Network: drop spoofed packets, ignore ICMP redirects and
source routing, SYN cookies. Kernel: hide kernel pointers and `dmesg` from
non-root users, no `kexec`, no SysRq, no unprivileged BPF, `ptrace_scope 1`.
Filesystem: protected symlinks and hardlinks in world-writable directories.

- **Can break.** Almost nothing. `ip_forward` and user namespaces are left on
  when Docker is installed. `--no-ipv6` turns IPv6 off entirely, so a
  provider-assigned v6 address stops answering.
- **Undo.** `securevps.sh revert sysctl`, then reboot or `sysctl --system`.

### kmodules

Blacklists kernel modules a VPS never loads, in
`/etc/modprobe.d/99-securevps.conf`: the filesystems cramfs, freevxfs,
jffs2, hfs, hfsplus and udf, and the network protocols dccp, sctp, rds and
tipc. Several have a history of bugs reachable by mounting a crafted image.

- **Can break.** Anything that speaks SCTP: `--no-protocols`. A module that
  is already loaded stays until reboot; `scan` warns.
- **Undo.** `securevps.sh revert kmodules`.

### pam

Password rules, in `/etc/security/pwquality.conf.d/99-securevps.conf`,
`/etc/security/faillock.conf` and six keys in `/etc/login.defs`: at least 12
characters from 3 character classes, no reuse of the last 5, a 15 minute
account lock after 5 failed attempts, yescrypt hashing, passwords expire
after a year. This applies to sudo and the console, which still take
passwords after SSH is key-only.

- **Can break.** Five sudo typos lock the admin for 15 minutes:
  `faillock --user deploy --reset`. The password expiry prompts the admin a
  year from now. `--tmout 900` logs idle shells out, which surprises people.
- **Undo.** `securevps.sh revert pam`.

### services

Stops and disables any of the following that are running, with
`systemctl disable --now`. Packages stay installed unless you pass
`--purge`. Writes no files.

| Service | What it is | Why a VPS does not need it |
|---|---|---|
| `rpcbind` | Port mapper for NFS and other RPC services | Only needed when this box serves or mounts NFS. |
| `avahi-daemon` | mDNS/Bonjour, finds printers and hosts on a LAN | There is no LAN. |
| `cups`, `cups-browsed` | Printing | There is no printer. |
| `nfs-server` | Network file sharing | Only if you deliberately export directories. |
| `inetd`, `xinetd` | Legacy launchers for small network services | Nothing modern uses them. |
| `telnet`, `rsh-server`, `talk` | Unencrypted remote login and chat from the 1980s | SSH replaced them. |
| `vsftpd` | FTP server | Unencrypted. Use SFTP, which sshd already provides. |
| `smbd`, `nmbd` | Samba, Windows file sharing | A share on the public internet is a breach waiting to happen. |
| `snmpd` | SNMP monitoring agent | Only with a monitoring system that polls it. |
| `ldap`, `slapd` | LDAP directory server | Only if this box is your directory. |
| `bind9` | DNS server | Only if this box is authoritative for a zone. |

- **Can break.** A box that is a DNS, NFS, Samba or LDAP server. Use
  `--keep bind9,nfs-server` for those. `--no-disable --verbose` reports
  without changing anything and lists every listening socket.
- **Undo.** `systemctl enable --now <service>` for each one, or
  `apt-get install` after `--purge`.

### time

Sets the timezone (UTC by default), installs chrony in place of
systemd-timesyncd, and checks the clock is synchronised. Writes
`/etc/chrony/conf.d/99-securevps.conf` only with `--ntp-server`.

- **Can break.** Nothing. Logs switch to UTC unless you pass
  `--timezone Europe/Zurich`.
- **Undo.** `timedatectl set-timezone <zone>`, `apt-get purge chrony`.

### logging

Makes the journal persistent in `/var/log/journal`, capped at 1 GB and one
month. Installs auditd with a light ruleset that records changes to
accounts, sudoers, sshd config, root's keys, module loading and the clock.
Files: `/etc/systemd/journald.conf.d/99-securevps.conf`,
`/etc/audit/rules.d/99-securevps.rules`.

- **Can break.** Nothing, but audit rules are locked once loaded, so a change
  to them takes effect at the next reboot. The journal uses up to 1 GB of
  disk.
- **Undo.** `securevps.sh revert logging`, then
  `systemctl disable --now auditd` and reboot.

### apparmor

Installs AppArmor and switches every profile that ships in complain mode
into enforce mode. A profile in complain mode logs what it would have
blocked and blocks nothing. Writes no files of its own; `aa-enforce` flips
the flag inside `/etc/apparmor.d`.

- **Can break.** A service whose profile was in complain mode for a reason.
  `journalctl -k | grep apparmor` shows denials;
  `aa-complain /etc/apparmor.d/<profile>` relaxes one profile.
- **Undo.** `aa-complain` per profile, or `systemctl disable --now apparmor`.

### banner

Replaces `/etc/issue`, `/etc/issue.net` and `/etc/motd` with a legal warning
and makes the Ubuntu motd scripts that print news and adverts
non-executable. The stock `/etc/issue.net` prints the distribution and
kernel version to anyone who connects, before they log in.

- **Can break.** Nothing.
- **Undo.** `securevps.sh revert banner`, then
  `chmod +x /etc/update-motd.d/*`.

### mounts

Writes a systemd mount unit that makes `/dev/shm` a tmpfs with
`nodev,nosuid,noexec`, a favourite staging area for exploits. `/tmp` and
`/var/tmp` are behind `--tmp` and `--var-tmp` because package installers and
container builds extract there and run what they extracted. Takes effect at
the next boot.

- **Can break.** With `--noexec-tmp`, anything that runs a binary out of
  `/tmp`. Default `/dev/shm` only: nothing.
- **Undo.** `securevps.sh revert mounts`, then reboot.

### vpn

Installs WireGuard or Tailscale. With `--ssh-vpn-only`, binds sshd to the
VPN address so the public port stops answering. A port that never appears in
a scan does not get brute forced. Needs setup on your side: a Tailscale
account, or WireGuard peers in `/etc/wireguard/wg0.conf` and
`firewall --allow 51820/udp`.

```sh
sudo securevps.sh vpn --provider tailscale --tailscale-authkey tskey-auth-...
sudo securevps.sh vpn --provider wireguard             # prints the server public key
```

- **Can break.** Your access. `--ssh-vpn-only` restarts sshd with no rollback
  timer. Test a login over the VPN before closing your session.
- **Undo.** `securevps.sh revert vpn`, then `systemctl restart ssh`.

### mfa

A TOTP code on top of the SSH key, via the Google Authenticator PAM module.
Accounts named in `--exempt-user` keep key-only login so deploys keep
working. Each user then enrols once with `google-authenticator`; until they
do, the key alone still works.

```sh
sudo securevps.sh mfa --enable --exempt-user deploy
```

- **Can break.** Your login, if you enrol wrong. Enrol from a session you
  keep open, test from a second one.
- **Undo.** `securevps.sh revert mfa`.

### alerts

A PAM hook that sends the user, source address and time of every interactive
login by mail or to a webhook. Often the first thing that tells you a key
has been copied. Mail needs a working MTA, which the script does not set
up; a webhook does not.

```sh
sudo securevps.sh alerts --login-alert --webhook https://hooks.example.com/services/T000/B000/xxx
```

- **Can break.** Nothing. A failing webhook is logged, not fatal.
- **Undo.** `securevps.sh revert alerts`.

### integrity

Installs AIDE, builds a baseline of the filesystem, and schedules a daily
comparison. Tells you what changed on disk after a suspected compromise.
The database sits on the host it is checking, so copy it elsewhere or an
attacker with root rewrites both.

```sh
sudo securevps.sh integrity --enable
journalctl -u securevps-aide.service                  # the last report
```

- **Can break.** Nothing. The first run takes minutes and the daily report is
  noise unless somebody reads it.
- **Undo.** `securevps.sh revert integrity`, `apt-get purge aide`.

### backup

Installs restic and a daily timer that backs up `/etc`, `/home`, `/root` and
`/var/lib` to a repository you supply, keeping 7 daily, 4 weekly and 6
monthly snapshots. Every other step reduces the chance of a bad day; this
one decides how bad the day is. Needs a repository, a password file kept
somewhere other than the server, and `restic init` run once by hand.

```sh
sudo install -d -m 0700 /etc/securevps
sudo sh -c 'umask 077; head -c 32 /dev/urandom | base64 > /etc/securevps/restic-password'
sudo securevps.sh backup --enable --repo sftp:backup@backup-host:/srv/restic/web1
sudo sh -c '. /etc/securevps/backup.env; export RESTIC_REPOSITORY RESTIC_PASSWORD_FILE; restic init'
sudo systemctl start securevps-backup.service        # first run, by hand
```

- **Can break.** Nothing on the server. Databases need a dump before the
  timer runs, not a file copy. A backup you have never restored is a
  hypothesis: `restic restore latest --target /tmp/restore-test` and look.
- **Undo.** `securevps.sh revert backup`.

## What the script will not do

- **Provider firewall.** Set it in the panel. It runs before the OS sees the
  packet, so it holds when the OS rules are wrong.
- **Snapshots, and one tested restore.** Restore one, look at what came
  back, then believe in it.
- **Reverse proxy and TLS.** Caddy, Traefik or nginx with Let's Encrypt. No
  admin interface on a public port: bind it to `127.0.0.1` and reach it
  over an SSH tunnel.
- **Secrets.** Not in shell history, not in image layers, `0600` on env files.
- **Your application.** A locked-down OS does nothing for an SQL injection.

## Requirements and tests

Debian 11+ or Ubuntu 22.04+, root, bash. Other distributions are refused
rather than half-supported.

```sh
sudo apt-get install -y debootstrap shellcheck
shellcheck securevps.sh
tests/readme-commands.sh                  # every command in this file must parse
sudo tests/integration/run.sh noble       # or jammy, bookworm
```

The integration suite builds a throwaway root filesystem, applies the steps,
scans, runs again to prove nothing changes twice, reverts, and checks that
both lockout guards refuse.

[Design notes](docs/design.md) cover the internals.
