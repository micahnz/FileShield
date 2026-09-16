#ifndef FILESHIELD_PIN_H
#define FILESHIELD_PIN_H

/*
 * Hash pinning for [allowlist] rules.
 *
 * Each rule's canonical binary pattern (the left-hand side exactly as
 * stored in RuleEntry.binary) is pinned to the SHA-512 of the concrete
 * binary that first matched it.  A later match with the same digest is a
 * silent grant; a changed digest needs an explicit user confirmation
 * before the pin is updated.  A glob rule therefore survives random
 * AppImage mount paths, while a different/tampered binary matching the
 * same glob re-prompts.
 *
 * One JSON state file backs the table:
 *
 *   {
 *     "pins": [
 *       {
 *         "pattern": "/tmp/.mount_XXX/openchamber",
 *         "sha512": "<128 hex characters>",
 *         "updated_at": 1757980000
 *       }
 *     ]
 *   }
 *
 * Parsing is STRICT and fail closed.  A missing file is the normal first
 * use (TOFU): an empty table and pin_damaged() == 0.  Every other open
 * error and every structural or value anomaly in an existing file marks
 * the WHOLE file damaged: pin_load() returns -1, pin_damaged() becomes 1
 * and the previously loaded entries stay untrusted until the next
 * successful load.  Individual bad entries are never dropped, because
 * dropping one would silently re-TOFU its rule.  Unknown keys are
 * ignored so newer state files stay loadable; blank lines and lines
 * starting with '#' are skipped like persist.c.  The parser expects the
 * line layout this module writes (one field per line) with top-level
 * unknown keys tolerated.
 *
 * The table holds at most PIN_MAX entries; pin_store() evicts the entry
 * with the smallest updated_at once the table is full (ties broken by
 * store order, oldest first).  Writes go through persist_write_text():
 * atomic O_EXCL temp + rename, 0600 file inside a root-only directory.
 *
 * This module is not thread-safe; the daemon is single-threaded.
 */

#define PIN_MAX 256
#define PIN_STATE_FILE "/var/lib/fileshield/allowlist-hashes.json"

/*
 * pin_check() results.  PIN_CHECK_DAMAGED is never a genuine mismatch:
 * it reports that the table cannot be trusted (pin_damaged() is set) or
 * that the arguments are unusable, so callers must fall through to the
 * normal prompt / no-silent-grant path.  PIN_CHECK_CHANGED (2) is only
 * returned for a stored entry whose digest differs from 'sha512'.
 */
#define PIN_CHECK_MATCH 0     /* stored digest equals sha512              */
#define PIN_CHECK_FIRST_USE 1 /* no entry for pattern (first use / TOFU)  */
#define PIN_CHECK_CHANGED 2   /* entry exists with a different digest     */
#define PIN_CHECK_DAMAGED 3   /* cannot check: damaged table or bad args  */

/*
 * Load the pin table from 'filepath', always replacing the whole table
 * on success (startup and every SIGHUP reload).  Pass NULL or "" to use
 * the current state file path: the PIN_STATE_FILE default or the
 * pin_set_state_file() override.
 *
 * Returns 0 when the file was loaded or does not exist (ENOENT yields an
 * empty table with pin_damaged() == 0 - normal first use).  Returns -1
 * and sets pin_damaged() == 1 with a LOG_ERR for any other open error
 * and for every structural or value anomaly, keeping the previously
 * loaded table untrusted (never a silent reset to an empty table).
 */
int pin_load(const char *filepath);

/*
 * 1 when the last pin_load() failed (unreadable/damaged file), 0 after a
 * clean load - including a missing file.  The pipeline must not grant
 * from the table while this is 1.
 */
int pin_damaged(void);

/*
 * Compare the stored pin for 'pattern' with 'sha512' (128 hex chars).
 * Side-effect free.  Returns PIN_CHECK_MATCH, PIN_CHECK_FIRST_USE,
 * PIN_CHECK_CHANGED with the stored digest copied into the 129-byte
 * old_out, or PIN_CHECK_DAMAGED when the table is damaged or the
 * arguments are unusable.  old_out is set to "" on every return path
 * except PIN_CHECK_CHANGED; it may be NULL when the caller does not need
 * the old digest.
 */
int pin_check(const char *pattern, const char *sha512, char old_out[129]);

/*
 * Insert 'pattern' (canonical absolute binary pattern, same key format
 * pin_load() validates) or refresh its digest and updated_at.  When the
 * table is full the entry with the smallest updated_at is evicted (ties:
 * oldest store first, a refresh counting as a store), so the table never
 * exceeds PIN_MAX entries.  The full table is then written atomically to
 * the current state file path.
 *
 * Returns 0 on success; -1 when the arguments are invalid, when the
 * table is damaged (repair the file and reload first - pin_store never
 * overwrites a damaged file), or when the write fails.  On a write
 * failure the in-memory entry is kept and a LOG_WARNING is emitted; the
 * next successful store or a restart re-reads the on-disk state.
 */
int pin_store(const char *pattern, const char *sha512);

/*
 * Override the state file path used by pin_store() (and by pin_load()
 * when passed NULL).  NULL or "" restores the PIN_STATE_FILE default.
 * Paths that do not fit are rejected with a LOG_ERR and leave the
 * previous path in effect.  Tests point this at a temp directory.
 */
void pin_set_state_file(const char *path);

#endif
