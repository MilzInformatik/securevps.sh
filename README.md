# securevps.sh

Hardening for a Debian or Ubuntu VPS. One Bash file, twenty steps. Each step
is its own command, takes flags, changes nothing the second time you run it,
and can be undone.

> **Disclaimer.** This script rewrites sshd, the firewall, PAM and kernel
> settings on a machine you probably cannot afford to lose. It comes with no
> warranty of any kind. You run it, you own the result. Read it before you run
> it, dry-run it, keep a provider console open, and test a second login before
> you close the first. If it locks you out or breaks an application, that is
> between you and your server.

```sh
curl -fsSLO https://raw.githubusercontent.com/MilzInformatik/securevps.sh/main/securevps.sh
less securevps.sh                 # it is about to edit sshd, read it first
sudo bash securevps.sh --dry-run  # every change as a diff, nothing written
sudo bash securevps.sh harden     # apply
```

The dry run prints a unified diff of every file the script would touch. You
see the sshd config before it is installed, not after.

## Contents

- [Setting up a new server](#setting-up-a-new-server)
- [Before you start](#before-you-start)
- [The command line](#the-command-line)
- [Commands](#commands): [harden](#harden), [scan](#scan), [revert](#revert), [confirm](#confirm), [help](#help)
- [How it keeps you out of trouble](#how-it-keeps-you-out-of-trouble)
- [The steps](#the-steps): [updates](#1-updates), [user](#2-user), [ssh](#3-ssh), [firewall](#4-firewall), [docker](#5-docker), [bruteforce](#6-bruteforce), [sysctl](#7-sysctl), [kmodules](#8-kmodules), [pam](#9-pam), [services](#10-services), [time](#11-time), [logging](#12-logging), [apparmor](#13-apparmor), [banner](#14-banner), [mounts](#15-mounts), [vpn](#16-vpn), [mfa](#17-mfa), [alerts](#18-alerts), [integrity](#19-integrity), [backup](#20-backup)
- [What the script will not do](#what-the-script-will-not-do)
- [Checking for drift](#checking-for-drift)
- [Requirements and tests](#requirements-and-tests)

## Setting up a new server

This is the sequence I run on every fresh box. Replace the address and the
ports with yours.

**On your own machine.** Skip the first line if you already have a key.

```sh
ssh-keygen -t ed25519
ssh-copy-id root@203.0.113.10
ssh root@203.0.113.10             # must work without a password prompt
```

**On the server, as root.** Install the script somewhere on `PATH` so the
`confirm` command works from a second session.

```sh
curl -fsSLO https://raw.githubusercontent.com/MilzInformatik/securevps.sh/main/securevps.sh
less securevps.sh
install -m 0755 securevps.sh /usr/local/sbin/
securevps.sh --dry-run --ssh-port 2222 --firewall-allow 80,443
securevps.sh harden    --ssh-port 2222 --firewall-allow 80,443
```

Two things happen during the run that need you at the keyboard. The `user`
step asks you to set a password for the new `deploy` account, because sudo
will ask for it later. The `ssh` step arms a five minute rollback timer and
prints the exact command to test with.

**In a second terminal, without closing the first.**

```sh
ssh -p 2222 deploy@203.0.113.10
sudo securevps.sh confirm         # cancels the rollback
```

**Back on the server.**

```sh
securevps.sh scan                 # every check should pass or skip
reboot                            # when convenient: mount options and kernel updates need one
```

Then do the things the script cannot do for you, listed under
[what the script will not do](#what-the-script-will-not-do). The provider
firewall and a tested snapshot restore are the two that matter most.

Common additions to the `harden` line:

```sh
securevps.sh harden --profile minimal                     # only the steps that cannot break an app
securevps.sh harden --docker-allow-published 80,443       # a container serves the web
securevps.sh harden --time-timezone Europe/Zurich         # logs in local time
securevps.sh harden --ssh-tcp-forwarding                  # you reach an admin UI over ssh -L
securevps.sh harden --user-sudo-nopasswd                  # no password prompt for the admin
securevps.sh harden --yes --ssh-rollback-timeout 0        # unattended, for cloud-init or CI
```

## Before you start

Two things need to be true before you touch sshd, and neither is in the
script's power to arrange.

**A console that does not go through SSH.** Hetzner, DigitalOcean, Vultr and
the rest all offer a web console. Find it and check it works now, not at the
moment you need it. Everything below is recoverable from a console and nothing
below is recoverable without one.

**An SSH keypair.** Every step assumes key-based login works. If it does not,
the `ssh` step refuses to run.

## The command line

```text
securevps.sh [command] [flags]
securevps.sh [flags] [command]        # order does not matter
```

The command is `harden`, `scan`, `revert`, `confirm`, `help`, or the name of a
step. No command means `harden`.

### Flag forms

Every setting is a flag. Inside a step's own command the prefix is optional.
With `harden` the prefix is required, because twenty steps share names like
`--enable` and `--schedule`.

```sh
securevps.sh ssh --port 2222                # short form, inside the step's own command
securevps.sh harden --ssh-port 2222         # prefixed form, works everywhere
securevps.sh harden --ssh-port=2222         # = works too
securevps.sh ssh --tcp-forwarding           # boolean on
securevps.sh ssh --no-tcp-forwarding        # boolean off
securevps.sh ssh --tcp-forwarding false     # explicit value, also accepted
securevps.sh harden --engine crowdsec       # unprefixed is fine when only one step has that flag
```

Lists are comma separated with no spaces: `--allow 80,443,25/tcp`.

### Global flags

| Flag | Short | Effect |
|---|---|---|
| `--dry-run` | `-n` | Print every change as a diff. Write nothing. |
| `--yes` | `-y` | Answer every prompt with yes. The sshd rollback timer still arms. |
| `--verbose` | `-v` | Explain each decision, list listening sockets, name failing sysctl keys. |
| `--quiet` | `-q` | Errors only. `scan` prints only failures and warnings. |
| `--json` | | Machine-readable output. Only `scan` produces anything useful with it. |
| `--profile P` | | `minimal` or `standard` (default). Which steps `harden` and `scan` cover. |
| `--only a,b` | | Run just these steps, in the fixed order below. |
| `--skip a,b` | | Run the profile without these steps. |
| `--no-backup` | | Do not copy files before editing them. `revert` cannot undo such a run. |
| `--force` | | Carry on past the two lockout guards. Do not. |
| `--run ID` | | `revert` only this run instead of all of them. |
| `--help` | `-h` | The built-in reference, with every flag and its default. |
| `--version` | `-V` | Print the version. |

Set `NO_COLOR=1` to turn colour off. Output is plain when stdout is not a
terminal.

### Profiles

| Profile | Steps | Use it when |
|---|---|---|
| `minimal` | updates, ssh, firewall, bruteforce, sysctl, time, banner | The box runs something you do not fully understand yet. None of these can break a running application. |
| `standard` | minimal plus user, docker, kmodules, pam, services, logging, apparmor, mounts | Default. Everything except the four opt-in steps. |

The opt-in steps are `integrity`, `mfa`, `vpn`, `alerts` and `backup`. They run
as part of `harden` only when their enable flag is given, and are one command
away otherwise: `securevps.sh mfa --enable`. There is no third profile.

### Order

`harden` always runs steps in this order, whatever you pass to `--only`:

```text
updates user firewall ssh docker bruteforce sysctl kmodules pam services
time logging apparmor banner mounts integrity mfa vpn alerts backup
```

The order matters in two places. `firewall` opens the new SSH port before
`ssh` moves sshd onto it. `docker` comes after `firewall` so its chain rules
survive a ufw reload.

### Exit codes

`harden` exits 1 when any step failed. `scan` exits 1 when any check fails.
Bad flags exit 1 before anything runs.

## Commands

### harden

Runs every step in the profile. A step that fails is reported and the run
carries on with the next one. At the end you get a change count, the notes
each step queued for you, and the `revert` command for this exact run.

```sh
sudo securevps.sh harden
sudo securevps.sh harden --profile minimal
sudo securevps.sh harden --only firewall,ssh --ssh-port 2222
sudo securevps.sh harden --skip user,apparmor
sudo securevps.sh harden --dry-run --verbose
sudo securevps.sh harden --yes                     # no prompts, for automation
```

Running a step's name instead of `harden` runs only that step, with the
short flag form available:

```sh
sudo securevps.sh firewall --allow 80,443
```

### scan

Read-only. One line per check, marked `pass`, `FAIL`, `warn` or `skip`.
Exits 1 on any `FAIL`. Run it as root, because some checks read `/etc/shadow`
and the iptables chains.

```sh
sudo securevps.sh scan
sudo securevps.sh scan --only ssh,firewall
sudo securevps.sh scan --quiet                     # only what is wrong
sudo securevps.sh scan --json | jq .summary
sudo securevps.sh scan --json | jq '.checks[] | select(.status=="fail")'
```

`scan` judges the host against the flags you give it. An opt-in step reports
`skip` until you pass its enable flag, and a custom setting is checked only if
you repeat it:

```sh
sudo securevps.sh scan --integrity-enable --mfa-enable
sudo securevps.sh scan --pam-min-length 16
```

The JSON shape:

```json
{
  "version": "0.1.0",
  "host": "web1",
  "os": "Debian GNU/Linux 12 (bookworm)",
  "summary": {"pass": 41, "fail": 0, "warn": 2, "skip": 6},
  "checks": [
    {"module": "ssh", "id": "password-auth", "status": "pass", "message": "password authentication is no"}
  ]
}
```

### revert

Every file the script edits is copied to `/var/backups/securevps/<run>/files/`
first and listed in that run's `manifest.tsv`. `revert` replays the manifests
backwards, newest run first, so a file ends up as it was before securevps.sh
ever touched it.

```sh
sudo securevps.sh revert                           # every run, every step
sudo securevps.sh revert ssh                       # only the sshd files
sudo securevps.sh revert ssh firewall bruteforce
sudo securevps.sh revert --run 20260907T101500Z-4242
sudo securevps.sh revert --dry-run                 # what would be restored
ls /var/backups/securevps/                         # the run IDs
```

`revert` restores files. It does not undo things done by running a command,
and it tells you which ones it skipped:

- **Root's password lock.** `passwd -u root`.
- **The admin account and its sudo membership.** `deluser deploy` if you want it gone.
- **Firewall rules.** `ufw reset`, or `systemctl disable --now nftables`.
- **Installed packages and enabled services.** They keep the old config file, but they are still running. Restart them, or reboot.
- **Kernel settings already applied.** They revert at the next boot once the file is gone.
- **The timezone.** `timedatectl set-timezone`.
- **The motd scripts made non-executable by `banner`.** `chmod +x /etc/update-motd.d/*`.

### confirm

Cancels the sshd rollback timer that the `ssh` step armed. Run it from the
new session, because that is the point: if the new session works, the config
is good.

```sh
sudo securevps.sh confirm
```

If nothing is armed it says so and exits 0. `scan` warns while a rollback is
pending.

### help

Prints every command, step, flag and default. It is generated from the same
table the parser uses, so it cannot go stale.

```sh
securevps.sh help
securevps.sh help | grep -A 20 '^  ssh$'          # one step's flags
```

## How it keeps you out of trouble

**Backups.** Every file is copied to `/var/backups/securevps/<run>/` before it
is edited, with mode preserved. `latest` is a symlink to the newest run.

**Drop-ins, not edits.** Config goes into `/etc/ssh/sshd_config.d`,
`/etc/sysctl.d`, `/etc/fail2ban/jail.d` and the like, with a `99-securevps`
prefix and a header saying the file is managed. The distribution's own files
stay untouched, so an upgrade does not fight the script. The files it must
edit in place (`/etc/login.defs`, `/etc/pam.d/su`, `/etc/pam.d/sshd`) get one
line changed or added, nothing more.

**Validation before reload.** Anything with a syntax checker is checked before
its service reloads: `sshd -t`, `nft -c`, `fail2ban-client -t`, `visudo -c`,
and a JSON parse of `daemon.json`. A failed check restores the backup and
marks the step failed. The rest of the run continues.

**Idempotent.** Running twice changes nothing the second time. `scan` after
`harden` is clean.

**Lockout guards.** Changing sshd over sshd is how people lose servers. Three
things stand in the way:

1. The `ssh` step refuses a config no account could log in through. If
   password auth is going off and no allowed account has a key, it stops.
2. The `user` step refuses to lock root's password until some non-root account
   has a key, is in the sudo group, and has either a password or a
   `NOPASSWD` rule. A key alone is not enough: `useradd` leaves the password
   locked, and sudo asks for one.
3. After a successful `sshd -t`, the `ssh` step arms a timer that puts the old
   config back in five minutes unless you `confirm` from a second session.

`--force` skips the first two. It exists for the case where you know something
the script does not, and it is the wrong answer to a guard you do not
understand.

## The steps

Each step below lists what it does, why, the files it writes, every flag with
its default, and examples. Flags are shown in the short form used with the
step's own command. Add the step name as a prefix when the flag goes on
`harden` or `scan`: `--port` becomes `--ssh-port`.

### 1. updates

Installs pending updates, then makes it keep happening without you.

**What it does.** Runs `apt-get upgrade`, removes orphaned packages and old
kernels, installs `unattended-upgrades` restricted to the security pocket
(on Ubuntu also the ESM pockets), and turns on the daily apt timers. Installs
`needrestart` set to restart patched services automatically. Automatic reboots
stay off unless asked for.

**Why.** Most compromised servers were not cleverly attacked. They ran a
version of something with a published advisory and nobody applied the patch.
Restarting services matters as much as the patch: updating a library does
nothing for a process that already mapped the old one.

**Writes.** `/etc/apt/apt.conf.d/99securevps-unattended`,
`/etc/apt/apt.conf.d/99securevps-periodic`,
`/etc/needrestart/conf.d/99-securevps.conf`.

| Flag | Default | Effect |
|---|---|---|
| `--upgrade` | `true` | Run a full package upgrade now. |
| `--auto` | `true` | Install and enable unattended-upgrades. |
| `--scope` | `security` | Which pocket auto-updates draw from. `all` adds the regular updates pocket. |
| `--autoremove` | `true` | Remove orphaned packages and old kernels after the upgrade. |
| `--auto-reboot` | | Reboot automatically at `HH:MM` when a patch needs it. Off when empty. |
| `--needrestart` | `true` | Restart services automatically after a library patch. |

```sh
sudo securevps.sh updates
sudo securevps.sh updates --auto-reboot 04:00       # reboot itself when a kernel lands
sudo securevps.sh updates --scope all               # every update, security or not
sudo securevps.sh updates --no-upgrade              # configure, do not upgrade right now
```

**Watch out.** `--scope all` means a broken point release can arrive at 06:00
without anyone watching. Security only is the safer default for a box nobody
babysits. With auto-reboot off, `scan` warns while a reboot is pending.

### 2. user

A non-root administrator, and root locked down behind it.

**What it does.** Creates the account with a home directory, adds it to the
`sudo` group, copies root's authorized keys to it (or the key you name), and
asks you to set its password. Sets `umask 027` for login shells, restricts
`su` to the sudo group with `pam_wheel`, and finally locks root's password.
The lock only happens after the guard described above passes.

**Why.** Working as root means every mistake is unlimited and the logs cannot
tell you who made it. One key per person, not one shared by the team, or the
audit log is useless and nothing can be revoked when somebody leaves.

**Writes.** `/home/<name>/.ssh/authorized_keys`,
`/etc/profile.d/99-securevps-umask.sh`, `/etc/sudoers.d/90-securevps-<name>`
(only with `--sudo-nopasswd`), one line each in `/etc/login.defs` and
`/etc/pam.d/su`.

| Flag | Default | Effect |
|---|---|---|
| `--create` | `true` | Create the administrator account. |
| `--name` | `deploy` | Its name. |
| `--ssh-key` | | A public key, or the path to one. Empty means root's `authorized_keys`. |
| `--shell` | `/bin/bash` | Login shell. |
| `--lock-root` | `true` | Lock root's password once the guard passes. |
| `--sudo-nopasswd` | `false` | Let the admin sudo without a password. Skips the password prompt. |
| `--umask` | `027` | Default umask for login shells. |
| `--restrict-su` | `true` | Only members of `sudo` may run `su`. |

```sh
sudo securevps.sh user
sudo securevps.sh user --name alice --ssh-key ~/.ssh/alice.pub
sudo securevps.sh user --ssh-key "ssh-ed25519 AAAA... alice@laptop"
sudo securevps.sh user --sudo-nopasswd                 # automation accounts
sudo securevps.sh user --no-lock-root                  # leave root's password alone
```

**Watch out.** The password prompt only appears on a terminal without
`--yes`. Unattended runs must pass `--sudo-nopasswd` or set a password
afterwards with `passwd deploy`; until then the step reports that it did not
lock root, and `scan` warns. Root can still log in with a key after the lock,
but the `ssh` step turns root login off, so after a full `harden` root is
console-only. `revert` does not unlock root: `passwd -u root`.

### 3. ssh

Key-only sshd with modern crypto and a rollback timer.

**What it does.** Writes a drop-in that turns off password and
keyboard-interactive auth, root login, and every kind of forwarding; limits
auth tries; restricts key exchange, ciphers and MACs to what OpenSSH 9 calls
safe; and stops advertising the Debian version. Removes the DSA host key,
generates an ed25519 key if missing, regenerates an RSA key under 3072 bits
at 4096, and trims `/etc/ssh/moduli` of DH groups under 3072 bits. On
socket-activated Ubuntu the port goes on `ssh.socket` instead. Then it
validates, reloads, arms the rollback timer, and tells you how to test.

**Why.** Turning password authentication off is the single most valuable line
in the file. It takes brute forcing, credential stuffing and every leaked
password off the table at once. Everything else here is worth less than that.

**Writes.** `/etc/ssh/sshd_config.d/99-securevps.conf` (mode 0600),
`/etc/systemd/system/ssh.socket.d/99-securevps.conf` when socket activated
and the port is not 22, `/usr/local/sbin/securevps-ssh-rollback` while the
timer is armed. Adds an `Include` line to an old `sshd_config` that lacks one.

The generated drop-in, trimmed:

```ini
Port 22
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
PermitEmptyPasswords no
AuthenticationMethods publickey
MaxAuthTries 3
MaxSessions 5
MaxStartups 10:30:60
LoginGraceTime 30
UsePAM yes
AllowGroups sudo
ClientAliveInterval 300
ClientAliveCountMax 2
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
GatewayPorts no
PermitTunnel no
DebianBanner no
Banner /etc/issue.net
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,...
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,...
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,...
```

| Flag | Default | Effect |
|---|---|---|
| `--port` | `22` | Port sshd listens on. |
| `--password-auth` | `false` | Allow password logins. |
| `--permit-root` | `no` | `PermitRootLogin`: `no`, `prohibit-password` or `yes`. |
| `--allow-users` | | `AllowUsers` list. Empty means no such line. |
| `--allow-groups` | `sudo` | `AllowGroups` list. Pass `""` to omit the line. |
| `--max-auth-tries` | `3` | `MaxAuthTries`. |
| `--login-grace` | `30` | `LoginGraceTime` in seconds. |
| `--client-alive` | `300` | `ClientAliveInterval` in seconds. Two missed probes drop the session. |
| `--tcp-forwarding` | `false` | Allow `ssh -L` and `ssh -R` tunnels. |
| `--agent-forwarding` | `false` | Allow `ssh -A`. |
| `--x11-forwarding` | `false` | Allow X11 forwarding. |
| `--gateway-ports` | `false` | Let remote hosts connect to forwarded ports. |
| `--modern-crypto` | `true` | Restrict KEX, ciphers, MACs and key types to the modern set. |
| `--regen-hostkeys` | `true` | Drop the DSA key, make sure ed25519 and RSA 4096 exist. |
| `--drop-ecdsa` | `false` | Also remove the ECDSA host key. Clients that pinned it will warn once. |
| `--moduli` | `true` | Remove DH moduli under 3072 bits. |
| `--disable-pam` | `false` | `UsePAM no`. Breaks faillock, MFA and login alerts. Leave it. |
| `--rollback-timeout` | `300` | Seconds before an unconfirmed change rolls back. `0` disables the timer. |

```sh
sudo securevps.sh ssh
sudo securevps.sh ssh --port 2222
sudo securevps.sh ssh --tcp-forwarding                  # needed for ssh -L tunnels
sudo securevps.sh ssh --allow-users deploy,alice
sudo securevps.sh ssh --permit-root prohibit-password --allow-groups ""
sudo securevps.sh ssh --rollback-timeout 600
sudo securevps.sh ssh --yes --rollback-timeout 0        # unattended, no timer
```

**The rollback flow.** After the reload the step prints:

```text
Do not close this session yet.
Open a second terminal and check you can still get in:

    ssh -p 2222 deploy@203.0.113.10

Then, in that new session, run:  securevps.sh confirm
If nobody confirms within 300s the old sshd config comes back by itself.
```

Say nothing and the old config returns on its own, with a line in the journal
tagged `securevps`. On a terminal the step also offers to confirm from the
same session, for when you already tested.

**Watch out.**

- **Changing the port alone locks you out.** The firewall only knows about the
  new port when it runs in the same invocation. Use
  `harden --only firewall,ssh --ssh-port 2222`, or run `firewall` first.
- **`--tcp-forwarding` is the default most likely to surprise you.** It is off,
  which breaks `ssh -L`. If you reach an admin UI bound to `127.0.0.1` through
  a tunnel, turn it back on.
- **`--permit-root prohibit-password` does nothing on its own.** Root is not
  in the `sudo` group, so `AllowGroups sudo` still blocks it. Pass
  `--allow-groups ""` as well, as in the example above.
- **Moving off port 22** stops essentially all background scanning noise and
  none of a targeted attack. Worth doing for the quieter logs, not as security.
- **`--yes` skips the prompt, not the timer.** Unattended runs need
  `--rollback-timeout 0`, or something that runs `confirm`.

### 4. firewall

Default-deny inbound with only the ports you asked for.

**What it does.** Deny inbound, allow outbound, deny routed. SSH is
rate-limited. Uses ufw if installed, nftables otherwise. Whatever sshd
listens on now and whatever it is about to listen on are both kept open, so
changing the SSH port in the same run cannot strand you.

**Why.** A service you forgot is listening is a service somebody else will
find. Ports 80 and 443 are not opened unless you ask, because plenty of
servers are not web servers and an open port should be a decision somebody
typed.

**Writes.** ufw: its own rule store, plus `IPV6=` in `/etc/default/ufw`.
nftables: `/etc/nftables.conf`, validated with `nft -c` before it loads.

| Flag | Default | Effect |
|---|---|---|
| `--backend` | `auto` | `ufw`, `nftables`, or whichever is installed. |
| `--enable` | `true` | Turn the firewall on. `false` writes rules without activating them. |
| `--allow` | | Extra ports to open: `80,443,25/tcp,51820/udp`. TCP unless told otherwise. |
| `--allow-from` | | Source-restricted rules: `10.0.0.0/8:5432,203.0.113.0/24:3306/tcp`. |
| `--ssh-limit` | `true` | Rate-limit new SSH connections (ufw `limit`). |
| `--ipv6` | `true` | Mirror every rule onto IPv6. |
| `--log-level` | `low` | `off`, `low`, `medium`, `high` or `full`. |
| `--block-ping` | `false` | Drop inbound ICMP echo. nftables backend only. |

```sh
sudo securevps.sh firewall
sudo securevps.sh firewall --allow 80,443
sudo securevps.sh firewall --allow 80,443,51820/udp
sudo securevps.sh firewall --allow-from 10.0.0.0/8:5432
sudo securevps.sh firewall --backend nftables --block-ping
sudo securevps.sh firewall --dry-run                     # the ufw commands it would run
```

**Watch out.** Configure your provider's firewall too, in their panel. It
filters before a packet reaches the OS, so it still works when the OS rules
are wrong, and it is the only reliable answer to the next step. The
`--allow-from` rules are additive: `--allow 5432` opens it to everyone,
`--allow-from` alone opens it to the listed sources only.

### 5. docker

Stop published container ports bypassing the firewall.

**What it does.** Puts a default `DROP` at the end of the `DOCKER-USER`
iptables chain, with established traffic, loopback, the private ranges
(`10/8`, `172.16/12`, `192.168/16`, `fc00::/7`) and anything you allow
returned before it. Installs a systemd unit that reapplies the rules after
every Docker restart, because a restart flushes the chain. Merges
`no-new-privileges`, `live-restore`, log rotation and the userland proxy
setting into `daemon.json`, keeping whatever else is in there. Skipped when
Docker is not installed.

**Why.** Docker writes its own iptables rules and they are evaluated before
ufw's. Run `docker run -d -p 5432:5432 postgres` on a server with
`ufw deny 5432` in place and Postgres answers the internet while `ufw status`
shows the deny rule doing nothing. This is documented behaviour, not a bug.
`DOCKER-USER` is consulted before Docker's own accept rules and Docker never
rewrites it, so a drop there holds.

**Writes.** `/etc/docker/daemon.json`,
`/usr/local/sbin/securevps-docker-firewall`,
`/etc/systemd/system/securevps-docker-firewall.service`.

| Flag | Default | Effect |
|---|---|---|
| `--firewall-fix` | `true` | Install the `DOCKER-USER` rules and the unit that reapplies them. |
| `--allow-from` | | Extra CIDRs allowed to reach published ports, IPv4 or IPv6. |
| `--allow-published` | | Container ports to expose publicly anyway: `80,443`. |
| `--daemon-config` | `true` | Manage `/etc/docker/daemon.json`. |
| `--no-new-privileges` | `true` | Block setuid escalation inside containers. |
| `--icc` | `true` | Allow container-to-container traffic on the default bridge. |
| `--live-restore` | `true` | Keep containers running while the daemon restarts. |
| `--userland-proxy` | `false` | Use the userland proxy instead of iptables hairpin NAT. |
| `--log-max-size` | `10m` | Per-container log size before rotation. |
| `--log-max-file` | `3` | Rotated log files to keep. |
| `--only-rules` | `false` | Reapply the `DOCKER-USER` rules from an earlier run and stop. |

```sh
sudo securevps.sh docker
sudo securevps.sh docker --allow-published 80,443       # the reverse proxy is public
sudo securevps.sh docker --allow-from 203.0.113.0/24    # the office can reach everything
sudo securevps.sh docker --no-icc                       # containers only talk on user-defined networks
sudo securevps.sh docker --only-rules                   # after fiddling with iptables by hand
```

Better still, bind containers to loopback and put a reverse proxy in front:

```yaml
services:
  db:
    image: postgres:16
    ports:
      - "127.0.0.1:5432:5432"
```

**Watch out.** The step reports three things it will not fix for you.
Containers publishing on `0.0.0.0`. Containers with `/var/run/docker.sock`
mounted, which are root on the host. Members of the `docker` group, which is
root by another name. A changed `daemon.json` restarts the daemon; with
`live-restore` on, containers survive that. `--no-icc` breaks any two
containers that talk over the default bridge instead of a named network.

### 6. bruteforce

Ban addresses that keep failing to log in.

**What it does.** fail2ban watching sshd in aggressive mode through the
systemd journal, on every port sshd uses: five failures in ten minutes earns
an hour's ban, and a `recidive` jail bans three-time offenders for a week.
The ban action matches the firewall backend. Your own address and loopback go
on the never-ban list. CrowdSec is supported if you installed it first.

**Why.** With key-only auth already in place this mostly saves log volume
rather than stopping a real attack, but log volume is worth saving. The
never-ban list is not optional in my view: fail2ban banning the administrator
during setup is a rite of passage nobody needs.

**Writes.** `/etc/fail2ban/jail.d/99-securevps.local`,
`/etc/fail2ban/jail.d/99-securevps-recidive.local`,
`/etc/fail2ban/fail2ban.d/99-securevps-log.conf`. Validated with
`fail2ban-client -t` before restart.

| Flag | Default | Effect |
|---|---|---|
| `--engine` | `fail2ban` | `fail2ban`, `crowdsec` or `none`. |
| `--maxretry` | `5` | Failures before a ban. |
| `--findtime` | `10m` | Window those failures are counted in. |
| `--bantime` | `1h` | How long a ban lasts. |
| `--recidive` | `true` | Ban repeat offenders for a week after three bans in a day. |
| `--aggressive` | `true` | Also match probes that never reach a password prompt. |
| `--ignore-ip` | | Addresses or CIDRs never to ban. |
| `--auto-ignore-ip` | `true` | Never ban the address this SSH session came from. |

```sh
sudo securevps.sh bruteforce
sudo securevps.sh bruteforce --maxretry 3 --bantime 24h
sudo securevps.sh bruteforce --ignore-ip 203.0.113.5,10.0.0.0/8
sudo securevps.sh bruteforce --engine crowdsec
sudo securevps.sh bruteforce --engine none
```

Useful afterwards:

```sh
sudo fail2ban-client status sshd
sudo fail2ban-client set sshd unbanip 198.51.100.7
```

**Watch out.** The auto-ignore reads the address from `SSH_CONNECTION`. Running
from a console or through `sudo -i` on some systems loses it, so pass
`--ignore-ip` for anything you must never lock out. The port list is taken
from sshd at run time; if you move the SSH port later without rerunning this
step, `scan` reports the mismatch.

### 7. sysctl

Kernel and network stack hardening.

**What it does.** Writes 40 settings and applies them live. Network:
reverse-path filtering, no source routing, no ICMP redirects in either
direction, SYN cookies, martian logging, no router advertisements. Kernel:
hide pointers and `dmesg` from unprivileged users, no `kexec`, no SysRq, no
unprivileged BPF, hardened BPF JIT, `ptrace_scope 1`, full ASLR. Filesystem:
protected symlinks, hardlinks, FIFOs and regular files in sticky directories,
no setuid core dumps. Skipped inside a container.

**Why.** These turn a local information leak into a dead end and drop spoofed
traffic before anything else sees it. `ip_forward` and unprivileged user
namespaces are left on when Docker is installed, because turning either off
breaks container networking entirely.

**Writes.** `/etc/sysctl.d/99-securevps.conf`.

| Flag | Default | Effect |
|---|---|---|
| `--network` | `true` | The network settings. |
| `--kernel` | `true` | The kernel settings. |
| `--filesystem` | `true` | The filesystem settings. |
| `--ipv6` | `true` | Keep IPv6 enabled. `--no-ipv6` disables it on every interface. |
| `--ip-forward` | `auto` | `on`, `off`, or `auto`, which is on when Docker is present. |
| `--ptrace-scope` | `1` | Yama `ptrace_scope`. `2` allows only root to attach, which breaks debuggers. |
| `--userns` | `true` | Keep unprivileged user namespaces. Containers need them. |

```sh
sudo securevps.sh sysctl
sudo securevps.sh sysctl --no-ipv6                  # provider gave you no IPv6 anyway
sudo securevps.sh sysctl --ptrace-scope 2           # no gdb or strace on other processes
sudo securevps.sh sysctl --ip-forward on            # this box is a VPN gateway
```

**Watch out.** `--no-ipv6` makes a provider-assigned IPv6 address stop
answering. `--ip-forward off` on a Docker host breaks published ports.
`scan --verbose` names each key that does not match.

### 8. kmodules

Blacklist filesystems and protocols a VPS never uses.

**What it does.** Blacklists 13 modules with both `blacklist` and
`install <mod> /bin/false`, so they cannot be loaded even on request, and
unloads any that are loaded and idle. Skipped inside a container.

**Why.** Drivers for filesystems and protocols no server touches are still
attack surface, and several of these have a history of bugs reachable by
mounting a crafted image. squashfs is deliberately absent because snap
packages will not mount without it.

**Writes.** `/etc/modprobe.d/99-securevps.conf`.

| Flag | Default | Effect |
|---|---|---|
| `--filesystems` | `true` | cramfs, freevxfs, jffs2, hfs, hfsplus, udf. |
| `--protocols` | `true` | dccp, sctp, rds, tipc. |
| `--firewire` | `true` | firewire-core, firewire-ohci, firewire-sbp2. |
| `--usb-storage` | `false` | usb-storage. Meaningless on a VPS, useful on hardware. |
| `--extra` | | More modules, comma separated. |

```sh
sudo securevps.sh kmodules
sudo securevps.sh kmodules --usb-storage
sudo securevps.sh kmodules --extra bluetooth,btusb
sudo securevps.sh kmodules --no-protocols            # something here speaks SCTP
```

**Watch out.** A module in use stays loaded until reboot; `scan` warns about
those.

### 9. pam

Password quality, lockout after repeated failures, ageing.

**What it does.** Minimum 12 characters from 3 character classes, no reuse of
the last 5, dictionary and GECOS checks, enforced for root too. Lockout for
15 minutes after 5 failures via `pam_faillock`, wired in through
`pam-auth-update` so it survives package upgrades. In `/etc/login.defs`:
yescrypt hashing, a 365 day maximum age, 14 days warning, 3 login retries,
60 second login timeout. Optionally an idle shell timeout.

**Why.** This matters even with key-only SSH, because sudo, the provider
console and every PAM-using service still take passwords. Key-only SSH does
nothing for an attacker who is already on the box.

**Writes.** `/etc/security/pwquality.conf.d/99-securevps.conf`,
`/etc/security/faillock.conf`, `/usr/share/pam-configs/securevps-faillock`,
`/etc/profile.d/99-securevps-tmout.sh`; one line in
`/etc/pam.d/common-password`; six keys in `/etc/login.defs`.

| Flag | Default | Effect |
|---|---|---|
| `--pwquality` | `true` | Enforce password complexity. |
| `--min-length` | `12` | Minimum password length. |
| `--min-classes` | `3` | Minimum character classes (upper, lower, digit, other). |
| `--remember` | `5` | Old passwords that cannot be reused. `0` turns history off. |
| `--faillock` | `true` | Lock an account after repeated failures. |
| `--faillock-deny` | `5` | Failures before the lock. |
| `--faillock-unlock` | `900` | Seconds until it unlocks by itself. |
| `--login-defs` | `true` | Manage `/etc/login.defs`. |
| `--pass-max-days` | `365` | Password maximum age. |
| `--tmout` | `0` | Idle shell timeout in seconds. `0` leaves shells alone. |

```sh
sudo securevps.sh pam
sudo securevps.sh pam --min-length 16 --min-classes 4
sudo securevps.sh pam --faillock-deny 3 --faillock-unlock 1800
sudo securevps.sh pam --tmout 900                     # idle shells exit after 15 minutes
sudo securevps.sh pam --no-login-defs                 # leave ageing and hashing alone
```

**Watch out.** faillock counts sudo failures too. Five typos and the admin
waits 15 minutes, or root runs `faillock --user deploy --reset`. Root locks
for 60 seconds under the same rule. The 365 day maximum age applies to the
admin's password as well; expect a change prompt a year from now. `TMOUT` is
exported read-only, so a user cannot unset it.

### 10. services

Stop and disable services a VPS rarely needs.

**What it does.** Stops and disables any of these that are running or
enabled: rpcbind, avahi-daemon, cups, cups-browsed, nfs-server, inetd,
xinetd, telnet, vsftpd, smbd, nmbd, snmpd, rsh-server, talk, ldap, slapd,
bind9. Packages stay installed unless asked. Warns when Postfix listens on
more than loopback. With `--verbose`, lists every listening socket and its
process.

**Why.** The cheapest attack surface reduction there is. A service that is not
running cannot be exploited, and most of these arrive as a dependency nobody
chose.

**Writes.** Nothing. It runs `systemctl disable --now`.

| Flag | Default | Effect |
|---|---|---|
| `--disable` | `true` | Stop and disable the services. `false` only reports. |
| `--purge` | `false` | Also uninstall them. |
| `--keep` | | Services from the list to leave alone. |
| `--extra` | | More services to disable. |

```sh
sudo securevps.sh services
sudo securevps.sh services --no-disable --verbose     # report only, with the socket list
sudo securevps.sh services --purge
sudo securevps.sh services --keep snmpd,bind9         # this box is a DNS server
sudo securevps.sh services --extra exim4,rpc-statd
```

**Watch out.** `scan` warns when more than two sockets listen on every
interface. That number is a nudge, not a rule; a web server with a mail
relay has three and that is fine.

### 11. time

A correct clock, which TLS and log correlation depend on.

**What it does.** Sets the timezone, installs chrony, disables
systemd-timesyncd, and verifies the clock is actually synchronised.

**Why.** Certificate validation and any attempt to line up two logs both fall
apart on a drifting clock. Not glamorous, and it breaks incident response
completely when it is wrong.

**Writes.** `/etc/chrony/conf.d/99-securevps.conf`, only with
`--ntp-server`.

| Flag | Default | Effect |
|---|---|---|
| `--chrony` | `true` | Install chrony. `false` keeps systemd-timesyncd. |
| `--timezone` | `UTC` | System timezone. |
| `--ntp-server` | | Override the distribution's NTP pool. |

```sh
sudo securevps.sh time
sudo securevps.sh time --timezone Europe/Zurich
sudo securevps.sh time --ntp-server ntp.example.internal
sudo securevps.sh time --no-chrony
```

**Watch out.** UTC is the default on purpose. Logs from several machines in
several timezones are a puzzle nobody enjoys at 03:00.

### 12. logging

Logs that survive a reboot, and an audit trail.

**What it does.** Persistent journal in `/var/log/journal`, compressed,
capped at 1G with a month of retention. auditd with a light ruleset: identity
files, sudoers, sshd config, root's keys, module loading, time changes, sudo
use, cron and systemd units. The rules are locked (`-e 2`) until reboot.
Optionally forwards syslog to a collector over TCP with a disk-backed queue.
auditd is skipped inside a container.

**Why.** Without this the journal lives in `/run` and is gone after a reboot,
which is exactly when you want to read it. The audit ruleset stays light by
default because the full CIS set is verbose enough to fill a small disk.

**Writes.** `/etc/systemd/journald.conf.d/99-securevps.conf`,
`/etc/audit/rules.d/99-securevps.rules`,
`/etc/rsyslog.d/99-securevps-remote.conf` with `--remote-syslog`.

| Flag | Default | Effect |
|---|---|---|
| `--journald` | `true` | Persistent journal with a size cap. |
| `--journal-max` | `1G` | Disk the journal may use. systemd units: `500M`, `2G`. |
| `--journal-retention` | `1month` | How long to keep entries. `2week`, `90day`. |
| `--auditd` | `true` | Install and enable auditd. |
| `--audit-rules` | `light` | `light`, `cis` or `none`. |
| `--remote-syslog` | | Forward everything to `host:port`. Port defaults to 514. |

```sh
sudo securevps.sh logging
sudo securevps.sh logging --journal-max 2G --journal-retention 90day
sudo securevps.sh logging --audit-rules cis
sudo securevps.sh logging --remote-syslog logs.example.com:6514
sudo securevps.sh logging --no-auditd
```

Reading it back:

```sh
sudo ausearch -k identity --start today
sudo ausearch -k privilege_used -i | tail
journalctl --disk-usage
```

**Watch out.** Because the audit rules are immutable once loaded, changing
`--audit-rules` takes effect at the next reboot. The syslog forward is plain
TCP with no TLS; send it over the VPN or put TLS in front yourself. Ship logs
off the host if you can: logs on a compromised host are evidence under the
attacker's control.

### 13. apparmor

AppArmor profiles in enforce rather than complain mode.

**What it does.** Installs AppArmor and its utilities, enables the service,
and moves every profile from complain into enforce. Skipped inside a
container.

**Why.** A profile in complain mode logs what it would have blocked and blocks
nothing, which is worth roughly nothing. Ubuntu ships profiles for several
network-facing services already; they only need to be enforcing.

**Writes.** Nothing. `aa-enforce` edits the profile flags in
`/etc/apparmor.d`.

| Flag | Default | Effect |
|---|---|---|
| `--enforce` | `true` | Put every complain-mode profile into enforce. `false` only installs and enables. |

```sh
sudo securevps.sh apparmor
sudo securevps.sh apparmor --no-enforce
```

Debugging a denial:

```sh
sudo aa-status
journalctl -k | grep apparmor
sudo aa-complain /etc/apparmor.d/usr.sbin.something      # relax one profile
```

### 14. banner

A legal warning banner, and no OS version before login.

**What it does.** Replaces `/etc/issue`, `/etc/issue.net` and `/etc/motd`
with a warning banner, and makes the Ubuntu motd scripts that print
help text, news and cloud adverts non-executable. The `ssh` step points sshd
at `/etc/issue.net` and sets `DebianBanner no`.

**Why.** The stock `/etc/issue.net` prints your distribution and kernel
version to anyone who opens a connection, before they authenticate. That is
free reconnaissance. The legal wording is also what makes unauthorised access
prosecutable in several jurisdictions.

**Writes.** `/etc/issue`, `/etc/issue.net`, `/etc/motd`. Changes mode on
`/etc/update-motd.d/{00-header,10-help-text,50-motd-news,51-cloudguest}`.

| Flag | Default | Effect |
|---|---|---|
| `--issue` | `true` | Write the banner to `/etc/issue` and `/etc/issue.net`. |
| `--motd` | `true` | Replace the dynamic motd. |
| `--file` | | Read the banner text from this file instead of the built-in one. |

```sh
sudo securevps.sh banner
sudo securevps.sh banner --file /etc/my-banner.txt
sudo securevps.sh banner --no-motd
```

**Watch out.** `revert` restores the three files but not the mode change:
`chmod +x /etc/update-motd.d/*` brings the Ubuntu motd back.

### 15. mounts

nodev, nosuid and noexec on the writable scratch directories.

**What it does.** Writes systemd mount units. `/dev/shm` becomes a tmpfs with
`nodev,nosuid,noexec` by default. `/tmp` as a tmpfs and `/var/tmp` as a bind
mount with the same flags are available behind flags. The units take effect
at the next boot. Skipped inside a container.

**Why.** `/dev/shm` is pure win: nothing legitimate executes or creates device
nodes there, and it is a favourite staging area for exploits that need
somewhere writable. `/tmp` and `/var/tmp` are opt-in because package
installers, language toolchains and container image builds all extract to
them and then run what they extracted, so `noexec` there breaks real things.

**Writes.** `/etc/systemd/system/dev-shm.mount`, `tmp.mount`, `var-tmp.mount`.

| Flag | Default | Effect |
|---|---|---|
| `--dev-shm` | `true` | `nodev,nosuid,noexec` on `/dev/shm`. |
| `--var-tmp` | `false` | `nodev,nosuid,noexec` on `/var/tmp`, as a bind mount of itself. |
| `--tmp` | `false` | Make `/tmp` a tmpfs (25% of RAM) with `nodev,nosuid`. |
| `--noexec-tmp` | `false` | Also `noexec` on `/tmp`. Expect breakage. |

```sh
sudo securevps.sh mounts
sudo securevps.sh mounts --var-tmp --tmp
sudo securevps.sh mounts --tmp --noexec-tmp
```

**Watch out.** A tmpfs `/tmp` lives in RAM. Big downloads or builds that use
`/tmp` should set `TMPDIR=/var/tmp`. Reboot when convenient, then run `scan`
to see the options in effect.

### 16. vpn

WireGuard or Tailscale, so SSH need not face the internet.

**What it does.** Installs Tailscale (from tailscale.com's install script)
or WireGuard. For WireGuard it generates a server key and writes a `wg0`
config with a commented peer template, then prints the server's public key.
For Tailscale it joins the tailnet if you pass an auth key. With
`--ssh-vpn-only` it binds sshd to the VPN address so the public port stops
answering, after checking the interface actually has an address.

**Why.** The strongest single change available. A port that never appears in
a public scan does not get brute forced, does not appear in a mass
exploitation campaign for the next OpenSSH CVE, and does not fill your logs.

**Writes.** `/etc/wireguard/wg0.conf` (mode 0600),
`/etc/ssh/sshd_config.d/97-securevps-vpn.conf` with `--ssh-vpn-only`.

| Flag | Default | Effect |
|---|---|---|
| `--provider` | `none` | `none`, `wireguard` or `tailscale`. |
| `--tailscale-authkey` | | Auth key for unattended enrolment. Without it, run `tailscale up` yourself. |
| `--wg-port` | `51820` | WireGuard listen port. |
| `--ssh-vpn-only` | `false` | Bind sshd to the VPN interface only. |

Tailscale, the easy path:

```sh
sudo securevps.sh vpn --provider tailscale --tailscale-authkey tskey-auth-...
sudo securevps.sh vpn --provider tailscale --ssh-vpn-only
```

WireGuard, which needs a few manual steps:

```sh
sudo securevps.sh vpn --provider wireguard             # prints the server public key
sudo securevps.sh firewall --allow 51820/udp           # the vpn step does not open the port
sudo vi /etc/wireguard/wg0.conf                        # add a [Peer] block per client
sudo systemctl enable --now wg-quick@wg0
sudo securevps.sh vpn --provider wireguard --ssh-vpn-only
```

A client config to match the generated server side:

```ini
[Interface]
PrivateKey = <client private key>
Address = 10.88.0.2/32

[Peer]
PublicKey = <server public key, printed by the vpn step>
Endpoint = 203.0.113.10:51820
AllowedIPs = 10.88.0.0/24
PersistentKeepalive = 25
```

**Watch out.** `--ssh-vpn-only` restarts sshd without a rollback timer. Test
a login over the VPN before closing your session. Keep the provider console
available, because the VPN is now a dependency of your access. `scan` needs
`--vpn-provider` repeated to check the VPN state.

### 17. mfa

A TOTP code on top of the SSH key.

**What it does.** Installs the Google Authenticator PAM module, includes it
in the sshd PAM stack with `nullok`, and tells sshd to run the
keyboard-interactive stage after the key. Accounts you name keep key-only
login so automated deploys keep working. Off by default. Refuses to run with
`--ssh-disable-pam`.

**Why.** A key is a file, and files get copied off laptops. A second factor
means a stolen key alone is not enough.

**Writes.** `/etc/pam.d/sshd.securevps-mfa`,
`/etc/ssh/sshd_config.d/98-securevps-mfa.conf`; one `@include` line in
`/etc/pam.d/sshd`.

| Flag | Default | Effect |
|---|---|---|
| `--enable` | `false` | Require a TOTP code in addition to the key. |
| `--exempt-user` | | Users that keep key-only login: `deploy,ci`. |

```sh
sudo securevps.sh mfa --enable --exempt-user deploy
```

Then, once per user, as that user:

```sh
google-authenticator -t -d -f -r 3 -R 30 -W          # scan the QR code, keep the scratch codes
```

Once everyone has enrolled, remove the `nullok` from
`/etc/pam.d/sshd.securevps-mfa` and reload sshd. Until then, an account
without a secret gets in with the key alone.

**Watch out.** Enrol yourself from a session you keep open, then test from a
second one. `scan` needs `--mfa-enable` repeated to check it.

### 18. alerts

Tell someone when a person logs in.

**What it does.** A PAM `session` hook that runs on every interactive SSH or
console login and sends the user, source address and time by mail, by
webhook, or both. The webhook receives `{"text": "SSH login: ..."}`, which
Slack, Mattermost and most chat tools accept as is. Off by default.

**Why.** Cheap, and often the first thing that tells you a key has been
copied. You know your own login times; an unexpected one at 03:00 is a signal
nothing else gives you that fast.

**Writes.** `/usr/local/sbin/securevps-login-alert`; one line in
`/etc/pam.d/sshd`.

| Flag | Default | Effect |
|---|---|---|
| `--login-alert` | `false` | Turn the hook on. |
| `--email` | | Address to mail. Installs `bsd-mailx`. |
| `--webhook` | | URL to POST to. |

```sh
sudo securevps.sh alerts --login-alert --email you@example.com
sudo securevps.sh alerts --login-alert --webhook https://hooks.example.com/services/T000/B000/xxx
sudo securevps.sh alerts --login-alert --email you@example.com --webhook https://hooks.example.com/x
```

**Watch out.** Mail needs a working MTA, which this script does not set up.
A webhook has no such dependency and is the better first choice. `scan` needs
`--alerts-login-alert` repeated to check it.

### 19. integrity

AIDE, so you can tell what changed on disk.

**What it does.** Installs AIDE, excludes the directories that change all the
time (logs, caches, spool, Docker layers, `/tmp`), builds the baseline
database, and schedules a check with a systemd timer. Results go to the
journal. Off by default.

**Why.** Tells you what changed on disk, which is the question you cannot
otherwise answer after a suspected compromise. Off by default because the
first run takes minutes and a daily report is noise unless somebody reads it.

**Writes.** `/etc/aide/aide.conf.d/99-securevps.conf`,
`/etc/systemd/system/securevps-aide.service` and `.timer`,
`/var/lib/aide/aide.db`.

| Flag | Default | Effect |
|---|---|---|
| `--enable` | `false` | Install AIDE and build the database. |
| `--schedule` | `daily` | systemd `OnCalendar` expression: `weekly`, `Mon *-*-* 03:00`. |

```sh
sudo securevps.sh integrity --enable
sudo securevps.sh integrity --enable --schedule weekly
```

Reading and refreshing it:

```sh
journalctl -u securevps-aide.service                  # the last report
sudo aideinit -y -f                                    # new baseline after deliberate changes
sudo scp /var/lib/aide/aide.db backup-host:aide/$(hostname).db
```

**Watch out.** The database sits on the host it is checking, so an attacker
with root rewrites both. Copy it somewhere else for it to mean anything.
`scan` needs `--integrity-enable` repeated to check it.

### 20. backup

restic and a timer, pointed at a repository you supply.

**What it does.** Installs restic, writes an environment file with the
repository and password file, and installs a daily timer that backs up
`/etc`, `/home`, `/root` and `/var/lib` (one filesystem, caches excluded),
then prunes to 7 daily, 4 weekly and 6 monthly snapshots. It will not invent
a destination and it does not initialise the repository. Off by default.

**Why.** Every other step on this page reduces the chance of a bad day. This
is the one that decides how bad the day is. A backup you have never restored
is a hypothesis.

**Writes.** `/etc/securevps/backup.env` (mode 0600),
`/etc/systemd/system/securevps-backup.service` and `.timer`.

| Flag | Default | Effect |
|---|---|---|
| `--enable` | `false` | Install restic and the scheduled job. |
| `--repo` | | restic repository URL. Required. |
| `--password-file` | `/etc/securevps/restic-password` | File holding the repository password. |
| `--schedule` | `daily` | systemd `OnCalendar` expression. |

Full setup, in order:

```sh
sudo install -d -m 0700 /etc/securevps
sudo sh -c 'umask 077; head -c 32 /dev/urandom | base64 > /etc/securevps/restic-password'
sudo securevps.sh backup --enable --repo s3:s3.amazonaws.com/my-bucket
sudo sh -c '. /etc/securevps/backup.env; export RESTIC_REPOSITORY RESTIC_PASSWORD_FILE; restic init'
sudo systemctl start securevps-backup.service        # first run, by hand
journalctl -u securevps-backup.service
```

S3-compatible stores also need credentials. Put them in the environment file,
which the unit already reads:

```sh
sudo tee -a /etc/securevps/backup.env >/dev/null <<'ENV'
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
ENV
```

Other repository forms:

```sh
sudo securevps.sh backup --enable --repo sftp:backup@backup-host:/srv/restic/web1
sudo securevps.sh backup --enable --repo /mnt/backup/web1 --schedule '*-*-* 02:00'
sudo securevps.sh backup --enable --repo rest:https://restic.example.com/web1 --password-file /root/.restic-pw
```

And the part that matters:

```sh
sudo sh -c '. /etc/securevps/backup.env; export RESTIC_REPOSITORY RESTIC_PASSWORD_FILE; restic restore latest --target /tmp/restore-test'
ls /tmp/restore-test/etc                              # then actually look at it
```

**Watch out.** Keep the password somewhere other than the server, or the
backup dies with it. Databases need a dump, not a file copy, for a consistent
backup; add a `pg_dump` or `mysqldump` to a cron job that runs before the
timer. To change the paths, override the unit with `systemctl edit
securevps-backup.service`, because the unit file itself is rewritten on the
next run.

## What the script will not do

Some things do not belong in a script, and doing them badly is worse than not
doing them.

- **Provider firewall.** Configure it in the panel. It runs before the OS sees
  the packet and it is the reliable answer to Docker's iptables behaviour.
- **Snapshots, and one tested restore.** Restore one, look at what came back,
  then believe in it.
- **Reverse proxy and TLS.** Caddy, Traefik or nginx. TLS 1.2 minimum, HSTS,
  Let's Encrypt. No admin interface on a public port: bind it to `127.0.0.1`
  and reach it over the VPN or an SSH tunnel.
- **Secrets.** Not in shell history, not in image layers, `0600` on env files.
  A real secret store once more than one person needs them.
- **DNS and mail.** CAA records. SPF, DKIM and DMARC if the box sends mail.
- **Your application.** Database users with the rights they need and no more,
  dependency updates, the framework's own guidance. A locked-down OS does
  nothing for an SQL injection.

## Checking for drift

`scan` works unattended and exits non-zero when something has changed. From
root's crontab:

```text
0 6 * * * /usr/local/sbin/securevps.sh scan --quiet || mail -s "drift on $(hostname)" you@example.com
```

Or feed the JSON to whatever watches your fleet:

```sh
sudo securevps.sh scan --json | jq -e '.summary.fail == 0'
```

Fixing drift is running `harden` again with the same flags.

## Requirements and tests

Debian 11+ or Ubuntu 22.04+, root, bash. Other distributions are refused
rather than half-supported. Python 3 is used where present, for merging
`daemon.json` and reading AppArmor's status.

```sh
sudo apt-get install -y debootstrap shellcheck
shellcheck securevps.sh
tests/readme-commands.sh                  # every command in this file must parse
sudo tests/integration/run.sh noble       # or jammy, bookworm
```

The integration suite builds a throwaway root filesystem, applies the steps,
scans, runs again to prove nothing changes twice, reverts, and checks that
both lockout guards refuse. A chroot has no systemd or host kernel, so
`firewall`, `sysctl`, `kmodules`, `mounts` and `apparmor` report as skipped
there; those five need a real VM.

[Design notes](docs/design.md) cover the internals.
