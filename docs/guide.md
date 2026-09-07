# Hardening a VPS

What to do to a new server, in the order I would do it, with the reasoning. The
script automates most of this. The last section is the part it should not.

## Before you start

Two things need to be true before you touch sshd, and neither of them is in the
script's power to arrange.

**You can reach a console that does not go through SSH.** Hetzner, DigitalOcean,
Vultr and the rest all offer a web console. Find it and check it works now, not
at the moment you need it. Everything below is recoverable from a console and
nothing below is recoverable without one.

**You have an SSH keypair.** If `ssh-keygen -t ed25519` is not something you have
run on the machine you are sitting at, run it now. Every step after this assumes
key-based login works.

```sh
ssh-copy-id root@your-server
ssh root@your-server        # must succeed without a password prompt
```

## 1. Patch, then keep patching

Most compromised servers were not cleverly attacked. They were running a version
of something with a published advisory and nobody applied it.

```sh
sudo securevps.sh updates
```

This upgrades what is installed and turns on `unattended-upgrades` restricted to
the security pocket, so it keeps happening without you. It also configures
`needrestart` to restart services automatically, which matters more than it
sounds: patching a library does nothing for the processes that already have the
old one mapped in.

Automatic reboots are off. Turn them on with `--updates-auto-reboot 04:00` if a
few minutes of downtime at a known hour is better than running a kernel with a
known hole, which for most people it is.

## 2. A user that is not root

```sh
sudo securevps.sh user --name deploy
```

Working as root means every mistake is unlimited and the logs cannot tell you who
made it. The module creates the account, puts it in `sudo`, copies root's
authorized keys across, and locks root's password.

That last step is guarded. It checks that some non-root account actually has a
key and sudo rights first, and refuses if not. A script that locks root on a box
with no other way in has not hardened anything, it has destroyed something.

One key per person, not one key shared by the team. A shared key makes the audit
log useless and cannot be revoked when somebody leaves.

## 3. SSH

```sh
sudo securevps.sh ssh
```

Password authentication off is the single most valuable line in the file.
Everything else on this list is worth less than that one.

Settings worth knowing about:

`--port 2222` moves sshd off 22. This stops essentially all of the background
scanning noise, and stops none of a targeted attack, which will find the port in
seconds. It is worth doing for the quieter logs, not because it is security.

`--tcp-forwarding` is off by default, which breaks `ssh -L`. If you reach an
admin UI bound to `127.0.0.1` through a tunnel, the way Dokploy suggests, you
need this on. It is the one default most likely to surprise you.

`--allow-groups sudo` means only members of `sudo` can log in at all. Service
accounts that should never have a shell then cannot get one even if their
password is somehow set.

`--disable-pam` is in here because Dokploy's guide recommends it, and it is off
by default because I think that recommendation is wrong for a general server. It
does remove a large chunk of authentication code from the path. It also disables
`pam_faillock`, account expiry, the login banner, session limits and TOTP. On a
single-purpose deploy target that trade is defensible. Getting it wrong on a box
with no usable key is unrecoverable without a console.

The rollback timer described in the README is on by default. Use it.

## 4. Firewall

```sh
sudo securevps.sh firewall --allow 80,443
```

Default deny inbound, allow outbound, SSH rate-limited. Ports 80 and 443 are not
opened unless you ask, because plenty of servers are not web servers, and an open
port should be a decision somebody typed.

Two firewalls are better than one. Configure your provider's firewall as well,
in their panel. It filters before a packet ever reaches the OS, so it still works
when the OS-level rules are wrong. It is also the only reliable answer to the
next section.

## 5. Docker, which ignores your firewall

This is the one that catches people, and it is worth being blunt about.

Docker writes its own iptables rules, and they are evaluated before ufw's. Run
this on a server with `ufw deny 5432` in place:

```sh
docker run -d -p 5432:5432 postgres
```

Postgres is now reachable from the internet. `ufw status` will show the deny rule
and it is doing nothing. This is not a Docker bug, it is documented behaviour,
and it means a great many people believe their database is firewalled when it is
answering the world.

```sh
sudo securevps.sh docker
```

The `DOCKER-USER` chain is consulted before Docker's own accept rules and Docker
never rewrites it. The module puts a default DROP there, allows RFC1918 sources
and loopback, and installs a systemd unit to reapply the rules after every Docker
restart, because restarting the daemon flushes that chain. This is the same
approach as [ufw-docker](https://github.com/chaifeng/ufw-docker).

To expose a container port publicly, say so:

```sh
sudo securevps.sh docker --allow-published 80,443
```

Better still, bind containers to loopback in the first place and put a reverse
proxy in front:

```yaml
ports:
  - "127.0.0.1:5432:5432"
```

Two other things this module reports but will not fix for you. Anyone in the
`docker` group can start a container that mounts the host filesystem, so that
group is root by another name; put people in it deliberately. And a container
with `/var/run/docker.sock` mounted is root on the host, which is fine for your
orchestrator and not fine for anything else.

## 6. Brute force

```sh
sudo securevps.sh bruteforce
```

fail2ban watching sshd, five failures per ten minutes, banned for an hour, plus a
`recidive` jail that bans repeat offenders for a week. With key-only auth already
in place this mostly saves you log volume rather than stopping a real attack, but
log volume is worth saving.

The address you are connected from goes on the never-ban list automatically. This
is not optional in my view; fail2ban banning the administrator during setup is a
rite of passage nobody needs.

Dokploy suggests aggressive mode, which also matches probes that never reach a
password prompt. `--bruteforce-aggressive` turns it on and costs nothing.

## 7. The kernel

```sh
sudo securevps.sh sysctl
sudo securevps.sh kmodules
```

Forty-odd `sysctl` settings: reverse-path filtering, no source routing, no
ICMP redirects, SYN cookies, martian logging, plus kernel restrictions like
`kptr_restrict` and `dmesg_restrict` that turn a local information leak into a
dead end. Then a blacklist of filesystems and network protocols a VPS never uses
but whose drivers are still attack surface.

`ip_forward` is left on when Docker is installed, because turning it off breaks
container networking entirely. Unprivileged user namespaces are likewise left
alone for the same reason.

## 8. Everything else

```sh
sudo securevps.sh harden        # or just do all of it at once
```

Password quality and lockout (`pam`), disabling services that should not be
listening (`services`), a synchronised clock (`time`, and TLS validation falls
apart without it), a journal that survives a reboot plus auditd (`logging`),
AppArmor in enforce rather than complain mode (`apparmor`), and a login banner
that no longer prints your exact OS version to anyone who connects (`banner`).

## 9. Optional, and worth it

**Take SSH off the public internet.** The strongest single change available:

```sh
sudo securevps.sh vpn --provider tailscale --tailscale-authkey tskey-...
sudo securevps.sh vpn --ssh-vpn-only
```

A port that never appears in a public scan does not get brute forced. Keep the
provider console available, because the VPN is now a dependency of your access.

**A second factor.** `securevps.sh mfa --enable` requires a TOTP code in addition
to the key. Use `--mfa-exempt-user deploy` so automated deploys keep working.

**File integrity.** `securevps.sh integrity --enable` installs AIDE and a daily
check. Copy the database off the host, or it is a file the attacker can rewrite
alongside everything else.

**Backups.** `securevps.sh backup --enable --backup-repo ...` installs restic and
a timer. It will not invent a destination for you.

## What the script will not do

Some things do not belong in a script, and doing them badly is worse than not
doing them.

**Provider-level firewall.** Configure it in the panel. It runs before your OS
sees the packet and it is the reliable answer to Docker's iptables behaviour.

**Snapshots, and one tested restore.** A backup you have never restored is a
hypothesis. Restore one, look at what came back, then believe in it.

**Reverse proxy and TLS.** Caddy, Traefik or nginx. TLS 1.2 minimum, HSTS,
certificates from Let's Encrypt. No admin interface on a public port: bind it to
`127.0.0.1` and reach it over the VPN or an SSH tunnel.

**Secrets.** Not in shell history, not baked into image layers, `0600` on env
files. Once more than one person needs them, a real secret store.

**Log shipping.** Logs on a compromised host are evidence under the attacker's
control. Send them somewhere else.

**DNS and mail.** CAA records. If the box sends mail, SPF, DKIM and DMARC.

**Your application.** Database users with the rights they need and no more,
dependency updates, and the framework's own security guidance. The OS being
locked down does nothing for an SQL injection.

## After the run

```sh
sudo securevps.sh scan
```

Then reboot at a convenient moment. Kernel module blacklists and mount options
only take effect at boot, and it is better to discover a boot problem while you
are paying attention than three weeks later.

Run `scan` again afterwards. It exits non-zero on any failure, so it works
unattended:

```
0 6 * * * /usr/local/sbin/securevps.sh scan --quiet || mail -s "drift on $(hostname)" you@example.com
```
