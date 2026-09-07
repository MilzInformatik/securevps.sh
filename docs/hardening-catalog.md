# VPS hardening catalog

Every control I propose to cover, grouped into the modules that will implement them.
Each module becomes a subcommand of `securevps.sh` and can run on its own.

Columns:

- **Default** is what happens on a plain `securevps.sh harden` with no flags.
- **Risk** is the chance of breaking a working server or locking you out.
  low = reversible and invisible, medium = can break an app, high = can end your session.

Sources of the recommendations: the Dokploy remote server security page, CIS Benchmarks for
Debian/Ubuntu, Lynis controls, `ssh-audit` hardening guides, and the Docker CIS benchmark.

Dokploy's page is short and checks eight things: UFW installed, active, default-deny inbound,
and only necessary ports open; SSH enabled with key auth and password auth off; fail2ban
installed, running, and protecting SSH. Everything it lists is in here. The rest of this
document is the surrounding work its checks assume you already did.

---

## 1. `updates` - patching

| Control | Default | Flag | Risk |
|---|---|---|---|
| `apt update && apt upgrade` once at run time | on | `--no-upgrade` | medium |
| Install and enable `unattended-upgrades` | on | `--no-auto-updates` | low |
| Restrict automatic updates to the security pocket | security only | `--auto-update-scope all` | low |
| Auto-remove unused dependencies and old kernels | on | `--no-autoremove` | low |
| Automatic reboot when a patch needs one | off | `--auto-reboot [HH:MM]` | high |
| `needrestart` in automatic mode so services pick up patched libraries | on | `--no-needrestart` | medium |
| Ubuntu Pro / Livepatch enrolment | off | `--livepatch <token>` | low |

Unattended security updates are the single highest-value control here. Most VPS compromises
I have seen are an unpatched public service, not a clever attack.

## 2. `user` - accounts and privilege

| Control | Default | Flag | Risk |
|---|---|---|---|
| Create a non-root admin user with sudo | on, name `deploy` | `--user <name>`, `--no-create-user` | low |
| Copy the current root `authorized_keys` to the new user | on | `--ssh-key <path or literal>` | low |
| Lock the root account password (`passwd -l`, keeps key login working) | on | `--keep-root-password` | medium |
| Require a password for sudo | on | `--sudo-nopasswd` | low |
| Set `umask 027` in `/etc/login.defs` and `/etc/profile.d` | on | `--umask <mask>` | low |
| Restrict `su` to the sudo group via `pam_wheel` | on | `--no-restrict-su` | low |
| Delete or lock unused system accounts with valid shells | report only | `--lock-unused-accounts` | medium |
| Audit for accounts with empty passwords and UID 0 duplicates | report | n/a | low |

The script refuses to lock root out until it has verified that the new user can log in with a
key and reach sudo. That check is the difference between hardening and bricking a box.

## 3. `ssh` - remote access

Written to `/etc/ssh/sshd_config.d/99-securevps.conf` so the distro's own config stays intact.

| Control | Default | Flag | Risk |
|---|---|---|---|
| `PasswordAuthentication no`, `KbdInteractiveAuthentication no` | on | `--allow-password-auth` | high |
| `PermitRootLogin no` | on | `--permit-root-login prohibit-password\|yes` | high |
| `PubkeyAuthentication yes` | on | n/a | low |
| Change the listen port | off, stays 22 | `--port <n>` | high |
| `AllowUsers` / `AllowGroups` allowlist | group `sudo` + admin user | `--allow-users`, `--allow-groups` | high |
| `MaxAuthTries 3`, `MaxSessions 5`, `MaxStartups 10:30:60` | on | `--max-auth-tries <n>` | low |
| `LoginGraceTime 30` | on | `--login-grace <s>` | low |
| `ClientAliveInterval 300`, `ClientAliveCountMax 2` | on | `--client-alive <s>` | low |
| Disable `X11Forwarding`, `AllowAgentForwarding`, `AllowTcpForwarding`, `PermitTunnel` | on | `--allow-tcp-forwarding`, `--allow-agent-forwarding` | medium |
| `PermitEmptyPasswords no`, `PermitUserEnvironment no`, `IgnoreRhosts yes` | on | n/a | low |
| `UsePAM no` once key-only auth is confirmed working | off | `--disable-pam` | high |
| Modern crypto only: curve25519 and DH group16+ KEX, chacha20/AES-GCM ciphers, ETM MACs | on | `--legacy-crypto` | medium |
| Regenerate host keys, drop DSA and small RSA, keep ed25519 + RSA 4096 | on | `--no-regen-hostkeys` | medium |
| Trim `/etc/ssh/moduli` to >= 3072-bit groups | on | n/a | low |
| `sshd -t` validation before any reload, automatic rollback if it fails | always | n/a | n/a |
| Keep the current session alive and open a second sshd on a spare port during the change | on | `--no-safety-net` | n/a |

Forwarding restrictions are the one place I expect pushback. `AllowTcpForwarding no` breaks the
SSH-tunnel pattern that Dokploy and similar tools use to reach an admin UI bound to localhost.
The flag is there for exactly that reason.

Dokploy's page recommends `UsePAM no` alongside key-only auth, and I have it behind a flag
rather than on by default. Turning PAM off does remove a large chunk of authentication code
from the path, but it also disables `pam_faillock`, account expiry, the login banner, session
limits, and the TOTP module in section 17. On a single-purpose deploy target that trade is
defensible. As a default for a general script it is not, and getting it wrong on a box with no
usable key is unrecoverable without console access.

## 4. `firewall` - packet filtering

| Control | Default | Flag | Risk |
|---|---|---|---|
| Backend | ufw if present, else nftables | `--backend ufw\|nftables` | low |
| Default policy: deny incoming, allow outgoing, deny routed | on | `--allow-forward` | medium |
| Allow the SSH port | always, follows `ssh --port` | `--ssh-port <n>` | high |
| Rate-limit SSH (`ufw limit`) | on | `--no-ssh-limit` | low |
| Open 80 and 443 | off | `--allow 80,443` | low |
| Restrict a port to a source CIDR | n/a | `--allow-from <cidr>:<port>` | low |
| IPv6 rules mirrored | on | `--no-ipv6` | medium |
| Log dropped packets at `low` | on | `--log-level <level>` | low |
| Drop inbound ICMP echo | off, ping stays up | `--block-ping` | low |

Ports 80 and 443 stay closed by default because plenty of VPSes are not web servers. Opening
a port should be a decision you typed, not one you inherited.

## 5. `docker` - container host hardening

This module matters more than any other on a Dokploy-style box.

| Control | Default | Flag | Risk |
|---|---|---|---|
| Fix the UFW bypass with `DOCKER-USER` chain rules, the same approach as `ufw-docker` | on when Docker is present | `--no-docker-firewall-fix` | medium |
| Allowlist source networks that may reach published container ports | RFC1918 + loopback | `--docker-allow-from <cidr>` | medium |
| `daemon.json`: `"no-new-privileges": true` | on | `--no-daemon-config` | medium |
| `daemon.json`: `"icc": false` (no default-bridge container-to-container traffic) | off | `--disable-icc` | high |
| `daemon.json`: `"live-restore": true` | on | n/a | low |
| `daemon.json`: json-file log rotation, 10m x 3 | on | `--log-max-size`, `--log-max-file` | low |
| `daemon.json`: `"userland-proxy": false` | on | `--keep-userland-proxy` | medium |
| User namespace remapping | off | `--userns-remap` | high |
| Warn on containers published to `0.0.0.0` and on `/var/run/docker.sock` mounts | report | n/a | low |
| Warn if any user other than root is in the `docker` group (equals root) | report | n/a | low |

Docker writes its own iptables rules and they are evaluated before UFW's. A container started
with `-p 5432:5432` is reachable from the internet even with `ufw deny 5432` in place. Anyone
who thinks their database is firewalled off is very often wrong about this. The fix is a rule
in `DOCKER-USER`, which Docker leaves alone. Dokploy's docs point at
[ufw-docker](https://github.com/chaifeng/ufw-docker) for this, and the rules this module writes
are the same idea. Whether to vendor that project or generate the chain rules directly is an
open question in the checklist below.

Dokploy also calls the provider's own firewall the reliable answer here, because it filters
before any packet reaches Docker's iptables rules. I agree, and it is why the provider firewall
is the first item in the manual section at the end of this document. The `DOCKER-USER` rules
are the belt; the provider firewall is the braces.

## 6. `bruteforce` - fail2ban or CrowdSec

| Control | Default | Flag | Risk |
|---|---|---|---|
| Engine | fail2ban | `--engine fail2ban\|crowdsec\|none` | low |
| sshd jail, `maxretry 5`, `findtime 10m`, `bantime 1h` | on | `--maxretry`, `--findtime`, `--bantime` | low |
| `recidive` jail: repeat offenders banned for a week | on | `--no-recidive` | low |
| Allowlist your current SSH client IP and RFC1918 | on | `--ignore-ip <cidr>`, `--no-auto-ignore-ip` | low |
| sshd jail `mode` | `normal` | `--aggressive` sets `mode = aggressive` | low |
| systemd journal backend | on | n/a | low |
| Ban action matched to the firewall backend | auto | n/a | low |
| CrowdSec: install the firewall bouncer and the ssh/http collections | when selected | `--crowdsec-collections` | low |

Allowlisting the IP you are connected from is not optional in my view. Fail2ban banning the
admin during setup is a rite of passage nobody needs.

Dokploy recommends the sshd jail's aggressive mode, which also matches probes that never get as
far as a failed password. With key-only auth already in place it mostly bans scanners you were
never at risk from, so it is a flag rather than a default. It costs nothing to turn on.

## 7. `sysctl` - kernel and network parameters

Written to `/etc/sysctl.d/99-securevps.conf`.

Network: reverse-path filtering on, source routing off, ICMP redirects neither accepted nor
sent, secure redirects off, `tcp_syncookies` on, broadcast ICMP ignored, bogus ICMP responses
ignored, martian packets logged, IPv6 router advertisements refused, `tcp_rfc1337` on.

Kernel: `kptr_restrict=2`, `dmesg_restrict=1`, `kexec_load_disabled=1`, `sysrq=0`,
`unprivileged_bpf_disabled=1`, `bpf_jit_harden=2`, `yama.ptrace_scope=1`,
`randomize_va_space=2`, `perf_event_paranoid=3`, `unprivileged_userns_clone` left on when
Docker is present because disabling it breaks rootless containers.

Filesystem: `protected_hardlinks`, `protected_symlinks`, `protected_fifos=2`,
`protected_regular=2`, `suid_dumpable=0`, core dumps disabled in limits and systemd.

| Flag | Effect |
|---|---|
| `--no-ipv6` | fully disable IPv6 via sysctl, off by default |
| `--allow-ip-forward` | keep `ip_forward` on, auto-detected and kept when Docker is present |
| `--profile paranoid` | adds `ptrace_scope=2` and disables user namespaces |

Risk: low, except IPv6 disabling and `ptrace_scope=2`, which breaks debuggers.

## 8. `kmodules` - kernel module blacklist

Blacklist rare filesystems (cramfs, freevxfs, jffs2, hfs, hfsplus, udf), rare network
protocols (dccp, sctp, rds, tipc), firewire, and `usb-storage` on headless boxes.
Default: filesystems and protocols on, `usb-storage` off. Flags: `--blacklist <mod>`,
`--no-blacklist <mod>`, `--blacklist-usb-storage`. Risk: medium, squashfs is deliberately not
blacklisted because snap packages need it.

## 9. `mounts` - filesystem options

`nodev,nosuid,noexec` on `/tmp`, `/var/tmp`, `/dev/shm`, and `nodev,nosuid` on `/home`.
`/tmp` as tmpfs via `systemd`'s `tmp.mount`. Default: on for `/dev/shm` and `/var/tmp`,
`/tmp` gets `nosuid,nodev` but keeps exec because some package installers and Docker builds
run scripts from there. `--noexec-tmp` opts in. Risk: medium to high. This module warns loudly
and offers `--revert`.

## 10. `pam` - passwords and login policy

Password quality through `pam_pwquality`: minimum 12 characters, 3 character classes, no
dictionary words, no reuse of the last 5. Lockout after 5 failures for 15 minutes through
`pam_faillock`. `/etc/login.defs`: `ENCRYPT_METHOD yescrypt`, `PASS_MAX_DAYS 365`,
`PASS_MIN_DAYS 1`, `PASS_WARN_AGE 14`, `UMASK 027`. Idle shell timeout of 15 minutes via
`TMOUT`, off by default. Flags: `--min-password-len`, `--no-faillock`, `--password-max-days`,
`--tmout <s>`. Risk: low, medium if you use password auth anywhere.

## 11. `services` - reduce what is listening

Report every listening socket with the owning process. Disable and optionally purge things a
VPS rarely needs: rpcbind, avahi-daemon, cups, nfs-server, telnetd, vsftpd, samba, snmpd,
postfix listening on external interfaces. Default: report and disable, do not purge.
Flags: `--purge`, `--keep <service>`, `--report-only`. Risk: medium, so the report comes first
and lists exactly what will stop.

## 12. `time` - clock sync

Install chrony or keep `systemd-timesyncd`, set the timezone to UTC, verify the clock is
synced. Default on, low risk. Flags: `--timezone <tz>`, `--ntp-server <host>`. Certificate
validation and log correlation both fall apart on a drifting clock.

## 13. `logging` - journald and auditd

Persistent journal in `/var/log/journal` with a 1G cap and 1 month retention. `auditd` with a
ruleset covering time changes, user and group edits, sudo use, module loading, and mounts.
Default: journald on, auditd on but with a light ruleset. Flags: `--audit-rules
light\|cis\|none`, `--journal-max-size`, `--remote-syslog <host>`. Risk: low, though the CIS
audit ruleset is noisy and can fill a small disk, which is why light is the default.

## 14. `integrity` - file integrity monitoring

AIDE with a database initialised after all other modules run, plus a daily check by timer.
Default: off, because the first run takes minutes and the daily mail is noise unless someone
reads it. Flags: `--enable`, `--aide-schedule <oncalendar>`. Risk: low.

## 15. `apparmor` - mandatory access control

Ensure AppArmor is installed, enabled in the bootloader, and that all profiles are in enforce
mode rather than complain. Default: on for Debian and Ubuntu. Flag: `--complain-mode`.
Risk: medium, an enforcing profile can block an app that worked before.

## 16. `banner` - login banners

Legal warning banner in `/etc/issue`, `/etc/issue.net`, and `/etc/motd`, with the OS version
and kernel removed from the pre-auth banner. `DebianBanner no` in sshd so the version string is
not advertised. Default on, low risk. Flag: `--banner-file <path>`.

## 17. `mfa` - second factor for SSH

TOTP through `pam_google_authenticator`, required in addition to the key rather than instead of
it, with an exemption for a named service account so deploys keep working. Default: off.
Flags: `--enable`, `--exempt-user <name>`. Risk: high, enrolment is interactive.

## 18. `vpn` - private admin access

Install WireGuard or Tailscale and move SSH behind it, so port 22 is not exposed at all.
Default: off. Flags: `--wireguard`, `--tailscale <authkey>`, `--ssh-vpn-only`. Risk: high, and
worth it. A server whose SSH port never appears in a public scan does not get brute forced.

## 19. `alerts` - notification on access

A PAM hook that sends mail or a webhook on every interactive SSH login, plus a daily digest of
fail2ban bans and available security updates. Default: off. Flags: `--email <addr>`,
`--webhook <url>`. Risk: low.

## 20. `backup` - restic scaffolding

Install restic, write a config template and a systemd timer, but do not invent a repository or
credentials. Default: off. Flags: `--repo <url>`, `--schedule`. Risk: low. A backup you have
never restored is a hypothesis, so the docs will cover the restore drill.

## 21. `scan` - read-only audit

Not a hardening step. `securevps.sh scan` reports what is and is not applied, exits non-zero
when something regressed, and can run under `--json` for monitoring. Optionally runs Lynis and
`ssh-audit` when they are installed.

---

## Documented but not automated

Some things a script should not touch. These go in the guide.

- Provider-level firewall in the Hetzner, Vultr, or DigitalOcean panel, in front of the OS
  firewall. It survives a misconfigured host.
- Snapshots and their retention, plus one tested restore.
- Reverse proxy TLS: Caddy, Traefik or nginx, TLS 1.2 minimum, HSTS, OCSP stapling, and no
  admin UI on a public port. Bind admin interfaces to `127.0.0.1` and reach them over an SSH
  tunnel or the VPN.
- Secrets: not in shell history, not in image layers, `0600` on env files, a real secret store
  once more than one person is involved.
- One SSH key per human, revoked when they leave. Shared keys make the audit log useless.
- Disabling the provider's password-based console recovery, or setting a strong password on it.
- DNS: CAA records, SPF, DKIM and DMARC if the box sends mail.
- Monitoring and log shipping off the host, because logs on a compromised host are evidence
  under the attacker's control.
- Database and application hardening, which is too app-specific to script.
