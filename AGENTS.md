# FileShield — Implementation Plan

## Language & Philosophy

- **C99**, no external dependencies beyond libc + Linux kernel headers
- **DRY / KISS**: no unnecessary abstraction, single-purpose functions, flat module structure

## Project Layout

```
FileShield/
├── AGENTS.md                    # this file (project guide)
├── README.md                    # user-facing documentation
├── Makefile
├── fileshield.conf              # default config shipped with install
├── fileshield.service           # systemd unit
├── src/
│   ├── main.c                   # daemonize, signals, startup/reload orchestration
│   ├── fanotify.c / fanotify.h  # init, marks, event loop, decision pipeline
│   ├── inode.c / inode.h        # protected-inode hash set (hard-link detection)
│   ├── config.c / config.h      # parse fileshield.conf
│   ├── cache.c / cache.h        # target-scoped, PID-keyed allow cache with TTL
│   ├── session.c / session.h    # in-memory session-scoped allow/deny decisions
│   ├── notify.c / notify.h      # kdialog-only two-stage popups
│   ├── persist.c / persist.h    # runtime allow/deny JSON state files
│   ├── sha512.c / sha512.h      # digests: helper fork for files, in-process strings/buffers
│   └── utils.c / utils.h        # /proc helpers, path matching, logging, home expansion
└── tests/
    ├── test_cache.c             # unit tests for cache module
    ├── test_config.c            # unit tests for config parser
    ├── test_session.c           # unit tests for session decisions
    ├── test_persist.c           # unit tests for JSON state files
    ├── test_sha512.c            # known-answer + differential digest tests
    ├── test_inode.c             # protected-inode set (exact keys, overflow)
    ├── test_fanotify.c          # mark mask, deferred queue, fingerprints, state loading
    ├── test_utils.c             # unit tests for utility functions
    └── bench_hotpath.c          # `make bench` microbenchmarks (not part of `make test`)
```

## Module Responsibilities

Headers are the source of truth for signatures; this table is the map.

| Module | Owns |
|--------|------|
| `main.c` | daemonize, signal flags, startup marks, `reload_protection()` with fail-closed rollback, persisted-state loading |
| `fanotify.c/h` | fanotify init/marks/mount marks (glob entries mark their static base), protected-path verdict (glob + `!` exclusion match, deny wins), per-event decision pipeline, runtime allow/deny lists, deferred-event queue, dialog pump |
| `inode.c/h` | open-addressing `(dev, ino)` set for hard-link detection (fixed capacity; overflow logs and degrades) |
| `config.c/h` | INI parse (`[protected_paths]`, `[allowlist]`, `[denylist]`, `[settings]`), `~` expansion, canonicalization, glob pattern compile (static base + suffix), `!` exclusions, TTL clamps |
| `cache.c/h` | PID+target allow cache with TTL and PID-reuse check (`/proc/<pid>/stat` start time) |
| `session.c/h` | POSIX-session-scoped allow/deny entries, leader-lifetime validity |
| `notify.c/h` | per-prompt session detection, user drop, environment whitelist, kdialog stages, fail-closed outcomes |
| `persist.c/h` | atomic JSON save (0600, `O_EXCL` temp + rename), tolerant line parser, fail-secure load |
| `sha512.c/h` | `sha512_file` (forked `sha512sum`), `sha512_proc_exe`, in-process `sha512_string`/`sha512_buf` |
| `utils.c/h` | `/proc` readers (`proc_exe_path`, `get_ppid`, `read_comm`, `read_cmdline`, `proc_stat_session`), `path_under`/`path_under_len`, protected-path glob matcher (`glob_base_len`, `glob_match_path`), home expansion, logging, `close_fds_from` |

### Event pipeline (decision order)

1. `event_resolve` — fd sanity, resolve target path, cache the protected-prefix verdict.
2. `event_fastpath` — mount-mark noise (unknown inode, unprotected path), dedup-cache hits.
3. `event_load_binary` — `/proc/<pid>/exe`; config denylist; hard-link classification.
4. `event_gather_identity` — comm/ppid/cmdline, binary SHA-512, call chain, session id; all
   gathered while the requester is kernel-suspended so `/proc` is still valid.
5. `event_runtime_denied` — session deny, runtime deny (full-cmdline fingerprint compared,
   computed lazily only when a runtime list can match).
6. `event_runtime_allowed` — skipped entirely for hard-link events; otherwise file cache →
   session allow → runtime allow → config allowlist.
7. `event_ask_user` — dialog rate limit, kdialog stages, decision recording.

### `notify.h` decision codes

```c
#define NOTIFY_ALLOW_ONCE 0     /* cached allow, file-scoped, user_ttl */
#define NOTIFY_DENY 1           /* deny this attempt only              */
#define NOTIFY_ALLOW_ALWAYS 2   /* persistent runtime allowlist entry  */
#define NOTIFY_DENY_ALWAYS 3    /* persistent runtime denylist entry   */
#define NOTIFY_ALLOW_SESSION 4  /* allow until the shell session ends  */
#define NOTIFY_DENY_SESSION 5   /* deny until the shell session ends   */
```

Both stages are `kdialog --yesnocancel` prompts whose bodies repeat the
binary, command and file.  Stage 1: Yes = allow once, No = grant scope,
Cancel = deny scope.  Stage 2 (grants): Yes = allow session, No = allow
always, Cancel = deny.  Stage 2 (denies): Yes = deny session, No = deny
always, Cancel = deny once.  kdialog's No button shares its exit code (1)
with some runtime errors, so a dialog that fails with exit 1 on the grant
stage can create a permanent rule -- a documented, accepted trade-off;
timeouts, exec failures and Cancel/window close always deny.  Scope text
states the real match keys: session = this binary + this exact file for
the session; always = file, command and call chain.

The dialog child forwards a whitelist of the user's session appearance
variables (desktop identity, Qt theme/scale, locale, cursor) read from
`/proc/<pid>/environ` so kdialog follows the desktop theme.  Display,
session-bus, `LD_*`, `PATH` and `QT_PLUGIN_PATH`/`QT_QPA_PLATFORM*` variables
are deliberately never forwarded: the prompt must stay on the display
FileShield detected, and no code-loading or platform override may come from
the requesting process.

### `main.c` — daemon lifecycle

```c
// Usage: fileshield [--foreground] [--config /path/to/fileshield.conf] [--debug]
// Signal handling: SIGTERM/INT -> shutdown, SIGHUP -> reload config
```

## Decision Scopes

| Decision | Match key | Lifetime | Stored in |
|----------|-----------|----------|-----------|
| Allow Once | PID + binary + target file | `user_ttl` (shipped config: 300s; 0 = not cached) | memory |
| Allow/Deny Session | SID + leader start + binary (+SHA-512) + target | `session_ttl` (0 = shell lifetime) | memory |
| Allow/Deny Always | binary SHA-512 + call chain + target file + command line (stored verbatim, matched by SHA-512 over the full raw line, ≤64 KB) | until removed | JSON state files |

Lookup order (a denial always wins): config denylist → session deny → permanent
deny → file cache → session allow → permanent allow → config allowlist →
dialog rate limit → prompt.  A hard-link event (protected inode reached through
a path outside every protected prefix) skips the grant stages entirely and
always prompts.  Persisted entries without a `target_path` or a recorded
command line, and entries whose fingerprint predates full-line hashing, do not
match (fail closed, re-prompt).

## Build & Test

- `make` — compile the `fileshield` binary
- `make test` — compile and run all test suites
- `make bench` — build and run `tests/bench_hotpath.c` (hot-path microbenchmarks)
- `make install` — install binary, config, systemd unit
- `make clean` — remove artifacts
- `make lint` — cppcheck static analysis
- `make debug` — ASan/UBSan build for the daemon
- CFLAGS: `-std=c99 -Wall -Wextra -Wpedantic -Werror -O2` plus hardening
  (`-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, PIE, RELRO/NOW)

## Testing Strategy

- **`test_cache`**: target-scoped insert/lookup/expire, wildcard vs file-scoped, PID reuse, TTL clamp
- **`test_config`**: parse valid/invalid .conf, ~ expansion, user_ttl/session_ttl, clamping, edge cases
- **`test_session`**: SID resolution, allow/deny matching, hash verification, TTL, dead leaders
- **`test_persist`**: save/load roundtrip, escaping, malformed input, truncation warnings
- **`test_sha512`**: FIPS 180-4 known-answer vectors, differential tests vs `sha512sum`, NUL-safe buffer hashing
- **`test_inode`**: exact-key lookup, device separation, duplicates, clear, overflow degradation
- **`test_fanotify`**: mark mask, deferred queue fail-closed flush, incomplete state entries dropped, command-line scoping, full-cmdline fingerprints, kernel queue saturation (root)
- **`test_utils`**: `proc_exe_path`, `/proc` readers, home expansion, `path_under`
- **`bench_hotpath`**: cache, path matching, SHA-512, runtime matchers, inode set, fast-path verdict, path resolution (`make bench`; kept only when a change wins)
- Tests are self-contained C files linked against the module `.o` files
- Each test returns 0 on pass, non-zero on failure. `make test` runs them all and reports aggregate.

## Limitations (see README for detail)
- Root-only (CAP_SYS_ADMIN for `fanotify_init`); root processes can bypass fanotify
- `kdialog` required for popups; missing/failing kdialog denies access (fail closed)
- Kernel 5.0+ for FAN_OPEN_PERM on directories; no NFS/CIFS coverage; `mmap` and bind-mount aliases are outside the threat model
- Hard links: inodes present at startup are tracked, and an open through an unprotected path always prompts. Files created after startup, deeper than 8 directory levels, or past the inode-table cap are not inode-tracked (`FAN_REPORT_FID` is a planned follow-up)
- Protected-path globs: `*` (one segment) and `**` (zero or more segments) only; `?`, `[`, `]` and `\` are literal. A glob entry marks its wildcard-free base directory (mount marks cover the filesystem beyond it), and a malformed pattern is rejected at load time (fail closed)
- Protected-path exclusions (`!pattern`): deny-wins and order-independent — an excluded path is never protected, never marked, and never inode-tracked; matching is path-based
- TOCTOU on binary identity between `/proc/<pid>/exe` and the hash check (inherent to fanotify permission systems)
- Dialog rate limiting: 20 prompts per binary within 60 s, then a 30 s deny cooldown
- Permanent _Always_ entries pin the exact command line, so invocations whose arguments change re-prompt
