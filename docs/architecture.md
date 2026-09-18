# Architecture

The pipeline runs for every `FAN_OPEN_PERM` event. Rules come from
`/etc/fileshield.conf`: `[protected_paths]` decide what is watched,
`[unsafe_allowlist]`, `[allowlist]` and `[denylist]` decide what is allowed
or denied, and `[settings]` tunes the cache TTLs, session caps and
notifications. A denial always wins over any grant.

## Decision Pipeline

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

## How It Works

1. The daemon calls `fanotify_init(FAN_CLOEXEC | FAN_NONBLOCK | FAN_CLASS_CONTENT | FAN_UNLIMITED_QUEUE, O_RDONLY | O_LARGEFILE)`. `FAN_UNLIMITED_QUEUE` is required for fail-closed semantics: with a bounded queue the kernel drops permission events on saturation and lets the access proceed. `FAN_NONBLOCK` keeps the group fd non-blocking so the event loop can `poll()` on `{group fd, signal-wake pipe}` — a signal arriving just before a blocking read would otherwise suspend shutdown/reload on an idle filesystem, and a supervisor SIGKILL in that window would let the kernel auto-allow every outstanding permission event.
2. It registers `FAN_OPEN_PERM | FAN_EVENT_ON_CHILD` marks on each protected path via `fanotify_mark()` (the child flag lets directory marks report accesses to their entries).
3. When a process opens a watched file, the kernel delivers a `fanotify_event_metadata` event and **blocks the calling process**.
4. The daemon resolves the binary path via `/proc/<pid>/exe` and evaluates the decision pipeline (config denylist, session/permanent denials, file cache, session/permanent grants, `[unsafe_allowlist]`, then the hash-pinned `[allowlist]`). Config-rule hits additionally raise the bounded `notify-send` tripwires described under [Notifications](configuration.md#notifications).
5. On a miss, it spawns a `kdialog --menu` popup on the requesting user's desktop session and reads the chosen row's tag from the dialog's stdout; a selection (zero exit + a known tag) is the only way to grant, so cancel, timeout, window close and any runtime failure deny the access (fail closed). The session is detected per prompt and applied only in the dialog child (the daemon's own environment is never modified), so a prompt for one user's process cannot appear on another user's desktop.
6. It writes a `struct fanotify_response` with `FAN_ALLOW` or `FAN_DENY` back to the fanotify fd.
7. The kernel unblocks the original syscall with the appropriate result.

## Why `fanotify`

Unlike approaches based on `inotify` or `auditd` alone, Fileshield uses `FAN_OPEN_PERM` events which suspend the syscall in the kernel until a decision is made. The file data is never read by the requesting process until you click Allow.
