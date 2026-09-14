# FileShield — Implementation Plan

## Language & Philosophy

- **C99**, no external dependencies beyond libc + Linux kernel headers
- **DRY / KISS**: no unnecessary abstraction, single-purpose functions, flat module structure

## Project Layout

```
FileShield/
├── Makefile
├── fileshield.conf              # default config shipped with install
├── fileshield.service           # systemd unit
├── docs/
│   └── plan.md                  # this file
├── src/
│   ├── main.c                   # daemonize, signals, orchestration
│   ├── fanotify.c / fanotify.h  # fanotify init, marks, event loop, responses
│   ├── config.c / config.h      # parse fileshield.conf
│   ├── cache.c / cache.h        # target-scoped, PID-keyed allow cache with TTL
│   ├── session.c / session.h    # in-memory session-scoped allow/deny decisions
│   ├── notify.c / notify.h      # kdialog-only two-stage popups
│   ├── persist.c / persist.h    # runtime allow/deny JSON state files
│   ├── sha512.c / sha512.h      # binary hashing helpers
│   ├── cli.c                    # fileshield-cli (list/remove/clear)
│   └── utils.c / utils.h        # /proc/<pid>/exe, path expansion, logging
└── tests/
    ├── test_cache.c             # unit tests for cache module
    ├── test_config.c            # unit tests for config parser
    ├── test_session.c           # unit tests for session decisions
    ├── test_persist.c           # unit tests for JSON state files
    ├── test_fanotify.c          # mark mask, deferred queue, state loading
    └── test_utils.c             # unit tests for utility functions
```

## Module API Design

### `utils.h` — shared helpers (no state)

```c
// Resolve /proc/<pid>/exe -> malloc'd path, or NULL on error
char *proc_exe_path(pid_t pid);

// Expand ~ and $HOME in path -> malloc'd string
char *expand_home(const char *path);

// Log to syslog + optional stderr (foreground mode)
void log_msg(int priority, const char *fmt, ...);

// Check if path is inside a watch directory
int path_under(const char *path, const char *dir);
```

### `config.h` — parse `fileshield.conf`

```c
#define MAX_PATHS 1024
#define MAX_ALLOWLIST 128

typedef struct {
    char path[PATH_MAX];
} ProtectedPath;

typedef struct {
    char binary[PATH_MAX];
    int  ttl_seconds;
} AllowlistEntry;

typedef struct {
    ProtectedPath  protected[MAX_PATHS];
    int            protected_count;

    AllowlistEntry allowlist[MAX_ALLOWLIST];
    int            allowlist_count;

    int            user_ttl_seconds;    /* Allow Once TTL (default 300)     */
    int            session_ttl_seconds; /* session decision cap (0 = shell) */
} Config;

// Parse config file into *cfg. Returns 0 on success, -1 on error.
int  config_load(const char *path, Config *cfg);
void config_free(Config *cfg);

// Singleton accessor for signal handler use
extern Config *g_config;
```

### `cache.h` — PID + target-file allowlist with TTL

```c
// Lookup: returns remaining TTL seconds (>0 covered) or 0 if absent.
// A NULL/"" target on insert = wildcard entry (config allowlist).
int cache_lookup(pid_t pid, const char *binary, const char *target);

// Insert with TTL (seconds from now). Overwrites the same (pid,binary,target).
void cache_insert(pid_t pid, const char *binary, const char *target,
                  int ttl_seconds);

// Lazy-expire: scan and remove dead entries
void cache_expire(void);

// Stats for tests
int cache_entry_count(void);
```

### `session.h` — in-memory session decisions

```c
// Resolve POSIX session id + session-leader start time for pid
int session_id_of(pid_t pid, pid_t *sid, unsigned long long *leader_start);

// Record/match file-scoped session decisions.  ttl 0 = leader lifetime.
void session_allow_add(pid_t sid, unsigned long long leader_start,
                       const char *binary, const char *sha512,
                       const char *target, int ttl_seconds);
int  session_allow_match(pid_t sid, const char *binary, const char *sha512,
                         const char *target);
void session_deny_add(...);
int  session_deny_match(...);

void session_expire(void);
void session_clear(void);
```

### `fanotify.h` — kernel interface

```c
// Init fanotify fd. Returns fd >= 0, or -1 on error.
int  fanotify_setup(void);

// Add/remove a mark on a single path. Returns 0 on success, -1 on error.
int  fanotify_add_mark(int fd, const char *path);
int  fanotify_remove_mark(int fd, const char *path);

// Blocking event loop. Returns on fatal error or signal.
void fanotify_loop(int fd);

// Respond to a pending event: FAN_ALLOW or FAN_DENY
int  fanotify_respond(int fd, const struct fanotify_event_metadata *ev, unsigned int response);
```

### `notify.h` — kdialog two-stage popup

```c
#define NOTIFY_ALLOW_ONCE 0     /* cached allow, file-scoped, user_ttl */
#define NOTIFY_DENY 1           /* deny this attempt only              */
#define NOTIFY_ALLOW_ALWAYS 2   /* persistent runtime allowlist entry  */
#define NOTIFY_DENY_ALWAYS 3    /* persistent runtime denylist entry   */
#define NOTIFY_ALLOW_SESSION 4  /* allow until the shell session ends  */
#define NOTIFY_DENY_SESSION 5   /* deny until the shell session ends   */

int notify_ask(const char *comm, pid_t pid, pid_t ppid,
               const char *comm_parent, const char *exe,
               const char *cmdline, const char *path, uid_t user_uid);
```

Stage 1 is `Allow Once / Allow / Deny`; `Allow` and `Deny` open a second
dialog offering session or permanent scopes.  Any failure (missing kdialog,
timeout, unexpected exit code) returns `NOTIFY_DENY` (fail closed).

### `main.c` — daemon lifecycle

```c
// Usage: fileshield [--foreground] [--config /path/to/fileshield.conf]
// Signal handling: SIGTERM/INT -> shutdown, SIGHUP -> reload config
```

## Decision Scopes

| Decision | Match key | Lifetime | Stored in |
|----------|-----------|----------|-----------|
| Allow Once | PID + binary + target file | `user_ttl` (default 300s) | memory |
| Allow/Deny Session | SID + leader start + binary (+SHA-512) + target | `session_ttl` (0 = shell lifetime) | memory |
| Allow/Deny Always | binary SHA-512 + call chain + target file | until removed | JSON state files |

Lookup order (a denial always wins): config allowlist (binary-wide) → session
deny → permanent deny → file cache → session allow → permanent allow →
dialog rate limit → prompt.  Persisted entries without a `target_path` are
dropped at load (fail closed).

## Build & Test

- `make` — compile `fileshield` binary + test binaries
- `make test` — compile and run all test suites
- `make install` — install binary, config, systemd unit
- `make clean` — remove artifacts
- `make lint` — cppcheck static analysis
- CFLAGS: `-std=c99 -Wall -Wextra -Wpedantic -O2`

## Testing Strategy

- **`test_cache`**: target-scoped insert/lookup/expire, wildcard vs file-scoped, PID reuse, TTL clamp
- **`test_config`**: parse valid/invalid .conf, ~ expansion, user_ttl/session_ttl, clamping, edge cases
- **`test_session`**: SID resolution, allow/deny matching, hash verification, TTL, dead leaders
- **`test_persist`**: save/load roundtrip, escaping, malformed input, remove with/without target
- **`test_fanotify`**: mark mask, deferred queue fail-closed flush, empty-target state entries dropped
- **`test_utils`**: proc_exe_path (mock /proc), home expansion, path_under
- Tests are self-contained C files linked against the module `.o` files
- Each test returns 0 on pass, non-zero on failure. `make test` runs them all and reports aggregate.

## Limitations (from README)
- Root-only (CAP_SYS_ADMIN for fanotify_init)
- `kdialog` required for popups; missing/failing kdialog denies access (fail closed)
- Kernel 5.0+ for FAN_OPEN_PERM on directories
- No NFS/CIFS coverage
