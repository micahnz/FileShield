#ifndef FILESHIELD_FANOTIFY_H
#define FILESHIELD_FANOTIFY_H

#include <sys/fanotify.h>
#include "config.h"
#include "persist.h"

int fanotify_setup(void);

/*
 * Add a mark for a protected path.
 * Returns 0 when the path was marked directly, 1 when the path does not
 * exist yet (skipped; a mount mark for its filesystem is ensured so a
 * later-created path is still intercepted), or -1 on a real error.
 */
int fanotify_add_mark(int fd, const char *path);

/*
 * Add the mark for one configured [protected_paths] entry.  Exact
 * entries mark the path directly (same contract as fanotify_add_mark);
 * glob entries mark their canonical wildcard-free base and enforce the
 * pattern at match time.  Return values match fanotify_add_mark().
 */
int fanotify_add_protected(int fd, const ProtectedPath *pp);

/*
 * Main event loop.  Blocks in poll() on {group fd, wake pipe} until an
 * event arrives, a signal handler writes to the wake pipe (read end;
 * pass -1 when there is none), or g_running/g_need_reload/g_fatal are
 * set.  The group fd must be non-blocking (FAN_NONBLOCK at init): the
 * wake pipe closes the window in which a signal arriving just before a
 * blocking read() would suspend shutdown/reload on an idle filesystem,
 * which would let a supervisor SIGKILL auto-allow outstanding
 * permission events on close(fan_fd).
 */
void fanotify_loop(int fd, int wake_fd);

/* Non-zero when at least one file/directory or filesystem/mount mark is active. */
int fanotify_any_mark_active(void);

/*
 * Scope guard: refuse a configuration whose own state directory or config
 * file could be intercepted by the marks it would install (the
 * self-deadlock class).  Runs against the currently published g_config;
 * returns 0 to proceed, -1 to refuse.
 */
int fanotify_scope_guard(const char *config_path);

/* Print the marks a config would install, without touching the kernel. */
void fanotify_dry_run(const Config *cfg);

/*
 * Event mask used for file and directory marks.  Directory-entry events
 * (FAN_CREATE, FAN_DELETE, FAN_MOVED_FROM, FAN_MOVED_TO, FAN_ATTRIB,
 * FAN_DELETE_SELF) require a group initialized with FAN_REPORT_FID and
 * make fanotify_mark() fail with EINVAL on this fd-based group, so they
 * must never be added here.  Exposed for the unprivileged regression test.
 */
unsigned int fanotify_mark_mask(void);

/*
 * Clear mount marks and inode table before a config reload.
 */
void fanotify_clear_marks(int fd);

/*
 * Drain pending FAN_OPEN_PERM events without blocking.
 * Auto-allows events from the dialog process group (dialog child and its
 * children, e.g. kdialog behind timeout(1)) and events from direct daemon
 * children.  Every other permission event runs the FULL decision pipeline
 * in defer mode: deny stages, caches and rule grants decide immediately,
 * so an allowlisted or denylisted read never queues behind the open
 * decision.  Only events that genuinely require the user are copied to a
 * deferred queue (their event fd stays open) and are replayed by the main
 * loop once the dialog finishes.  Closing such an event fd instead would
 * leave the caller's open() blocked forever and leak a kernel permission
 * event.  A nested pump (re-entered from inside a defer-mode decision,
 * e.g. by a hashing helper wait) falls back to the cheap fast-path allow
 * and defers the rest instead of recursing into the pipeline.
 * Called by notify.c while waiting for the dialog child to finish.
 * Returns the number of events responded to immediately.
 */
int fanotify_pump(int fan_fd, pid_t dialog_child_pid);

/*
 * Queue a read-but-undecided permission event for replay by the main
 * loop; the kernel event fd must stay open.  Returns 0 when queued,
 * -1 when the pending queue is full — the caller must then respond
 * fail-closed (FAN_DENY) and close the event fd.
 */
int fanotify_defer_event(const struct fanotify_event_metadata *ev);

/*
 * Deny and close every deferred permission event.  Called when the
 * kernel reports FAN_Q_OVERFLOW (saturation) and on config reload and
 * shutdown; fail closed.
 */
void fanotify_flush_pending(int fan_fd);

/*
 * Deny and close every FAN_OPEN_PERM event still queued in the kernel.
 * Must run before close(fan_fd) on shutdown: the kernel responds
 * FAN_ALLOW to outstanding permission events when the group fd is
 * closed, so the queue has to be drained and denied first (fail closed).
 */
void fanotify_drain_and_deny(int fan_fd);

/*
 * Dynamic allowlist / denylist persistence: load root-only state files
 * into the in-memory lists (called on daemon startup and reload).
 */

/* Load persisted entries into the dynamic allowlist. Called on daemon startup. */
void fanotify_load_dyn_allowlist(const PersistEntry *entries, int count);

/* Load persisted entries into the dynamic denylist. Called on daemon startup. */
void fanotify_load_dyn_denylist(const PersistEntry *entries, int count);

/*
 * Test seams: evaluate the loaded runtime lists against a synthetic
 * request with a zero-depth call chain.  Used by test_fanotify to
 * regression-test target and command-line scoping without a kernel
 * permission event.  cmdline_fp is the full-cmdline fingerprint exactly
 * as an event would compute it ("" = unverifiable, which never matches);
 * tests and the benchmark build it with sha512_string().
 */
int fanotify_test_dyn_allow_match(const char *binary, const char *bin_sha512,
                                  const char *target, const char *cmdline_fp);
int fanotify_test_dyn_deny_match(const char *binary, const char *bin_sha512,
                                 const char *target, const char *cmdline_fp);

/*
 * Test seams: evaluate the loaded config rule sections against a
 * synthetic request.  Unprivileged, no kernel permission event needed.
 * All three use the same matchers as the pipeline, including glob
 * binaries/targets.
 *
 * fanotify_test_config_allow_match() returns the matched [allowlist]
 * rule's canonical binary pattern (the hash-pin key), or NULL when no
 * rule matches.  When grant_target is non-NULL it receives the rule's
 * target_path, or NULL for a global rule (wildcard cache entry).
 *
 * fanotify_test_unsafe_allow_match() does the same for
 * [unsafe_allowlist], which never participates in hash pinning.
 *
 * fanotify_test_config_deny_match() returns the [denylist] verdict:
 * non-zero when a rule matches (deny wins), 0 otherwise.
 */
const char *fanotify_test_config_allow_match(const char *binary,
                                             const char *target,
                                             const char **grant_target);
const char *fanotify_test_unsafe_allow_match(const char *binary,
                                             const char *target);
int fanotify_test_config_deny_match(const char *binary, const char *target);

/*
 * Test seams: the [allowlist] hash-pin verdict without a kernel event.
 * fanotify_test_allowlist_verdict() runs the same decision the pipeline
 * uses for the first rule matching (binary, target):
 *   0 ALLOW            stored pin matches; a first-use rule is also
 *                      reported as ALLOW because the pipeline stores the
 *                      digest and grants (the store itself is covered by
 *                      fanotify_test_pin_first_seen())
 *   1 CHANGED          stored digest differs; the previous digest is
 *                      copied into old_out
 *   2 NO_SILENT_GRANT  pin table damaged or bin_sha512 empty/missing
 *   3 NO_MATCH         no [allowlist] rule matches
 * Side-effect free: it never stores a pin and never prompts.
 *
 * fanotify_test_pin_first_seen() performs the pipeline's first-seen
 * store: when (binary, target) matches an [allowlist] rule that has no
 * pin yet it calls pin_store() on the rule's canonical binary pattern,
 * which writes the state file immediately and atomically.  Returns 0 on
 * success; -1 when no rule matches, the rule already has a pin, or the
 * store fails.
 */
int fanotify_test_allowlist_verdict(const char *binary,
                                    const char *bin_sha512,
                                    const char *target,
                                    char old_out[129]);
int fanotify_test_pin_first_seen(const char *binary,
                                 const char *bin_sha512,
                                 const char *target);

/*
 * Test seam: fingerprint a live process's full raw command line the same
 * way the event pipeline does (NUL-separated bytes, bounded).  Returns 0
 * on success and fills hex_out, -1 when the cmdline is unreadable/empty.
 */
int fanotify_test_cmdline_fingerprint(pid_t pid, char hex_out[129]);

/*
 * Test seam: the fast path's "mount-mark noise" verdict for a synthetic
 * (dev, ino, path) — the same condition event_fastpath uses to allow an
 * event instantly.  Used by bench_hotpath to measure the per-event
 * classification cost at realistic table sizes.
 */
int fanotify_test_fastpath_allows(dev_t dev, ino_t ino, const char *path);

/*
 * Test seam: resolve an open fd to its path exactly like the event
 * pipeline does (including the " (deleted)" marker stripping).  Lets
 * test_fanotify pin the unlinked-file behavior without a kernel
 * permission event.
 */
int fanotify_test_resolve_path(int fd, char *out, size_t outsz);

/*
 * Test seam: the unsafe-hit per-process gate.  Returns 1 the first time
 * (pid, start time) is seen and records it, 0 on every later call for the
 * same process.  Used by test_fanotify without a kernel permission event.
 */
int fanotify_test_unsafe_first_hit(pid_t pid);

/*
 * Test seams: init-namespace mount-mark plumbing.  fanotify_test_mark_path()
 * builds "/proc/1/root" + path (0 on success, -1 when it does not fit);
 * fanotify_test_mount_id() returns the init-namespace mount ID of the mount
 * containing path, or 0 when statx(STATX_MNT_ID) is unavailable.
 */
int fanotify_test_mark_path(const char *path, char *out, size_t outsz);
unsigned long long fanotify_test_mount_id(const char *path);

/*
 * Test seams: the recent-decision dedup cache.  The key is
 * (pid, dev, ino, resolved path); a newer decision replaces an older one
 * for the same key, and a reload clears the cache.
 */
void fanotify_test_recent_insert(pid_t pid, dev_t dev, ino_t ino,
                                 const char *target, int decision);
int fanotify_test_recent_lookup(pid_t pid, dev_t dev, ino_t ino,
                                const char *target);
void fanotify_test_recent_clear(void);

/*
 * Test seam: run the real verdict stages (denials before grants) over a
 * synthetic request.  Returns 1 when a deny stage decided, 2 when a grant
 * stage decided, 0 when the event would reach the dialog.  sid > 0 marks
 * the synthetic context as a member of that session; cmdline_fp may be
 * NULL; hardlink mirrors the pipeline's hard-link classification (which
 * strips every grant).
 */
int fanotify_test_verdict_stage(const char *binary, const char *bin_sha512,
                                const char *target, const char *cmdline_fp,
                                pid_t sid, int hardlink);

/* Test seam: the per-binary dialog rate limiter. */
int fanotify_test_dialog_rate_limited(const char *binary);

/*
 * Test seam: record a mark-table entry like a real installation (no
 * kernel call), so unprivileged reload tests can start from a state
 * where marks are active and exercise the "rollback left no active
 * marks" shutdown branch.  Returns 0 on success, -1 when the table is
 * full; fanotify_clear_marks() removes it again.
 */
int fanotify_test_seed_mark(const char *path);

#endif
