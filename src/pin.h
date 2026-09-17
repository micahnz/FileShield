#ifndef FILESHIELD_PIN_H
#define FILESHIELD_PIN_H

#include <limits.h> /* PATH_MAX */
#include <time.h>   /* time_t   */

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
 * pin_load_file()/pin_write_file() are the same parser and serializer
 * without daemon state: fileshield-cli uses them to read and write the
 * pin file directly when the daemon is stopped, and the daemon's
 * pin_load()/pin_store() are built on them.  A pin row's ID is not
 * stored: it is the first RULEID_HEX_LEN (16) hex characters of
 * SHA-512 over the row's pattern, computed on demand (ruleid.h).
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
 * One serialized pin row: the shape stored in allowlist-hashes.json and
 * the unit of the pure file API.  The live daemon table adds a
 * store-order tie-break that is never persisted, so it is not part of
 * the public shape.
 */
typedef struct
{
    char pattern[PATH_MAX];
    char sha512[129];
    time_t updated_at;
} PinRecord;

/*
 * Pure file API: load 'filepath' into out[0..max-1] with the strict
 * fail-closed parse described above, without touching daemon state (the
 * damage verdict is reported through damaged_out, not pin_damaged()).
 *
 * Requires a non-empty filepath, out != NULL and max >= 1; anything
 * else returns -1 with *damaged_out = 1.
 *
 * Returns the number of rows loaded (>= 0) on success, with
 * *damaged_out = 0.  A missing file is the normal empty table (0 rows,
 * not damaged).  Any other open error, and every structural or value
 * anomaly, returns -1 with *damaged_out = 1.  A file holding more rows
 * than max is damage: rows are never silently dropped, so callers
 * managing the daemon's file pass max = PIN_MAX.  On an open or parse
 * failure (and for a missing file) out[0..max-1] is zeroed, never left
 * partially filled, so a partial table can never be mistaken for a
 * loaded one; argument errors return before out is touched.  damaged_out
 * may be NULL when the caller does not need the flag.
 */
int pin_load_file(const char *filepath, PinRecord *out, int max,
                  int *damaged_out);

/*
 * Serialize rows[0..count-1] and write them atomically to filepath via
 * persist_write_text().  Requires a non-empty filepath, count in
 * 0..PIN_MAX (a larger table would make the daemon load the file as
 * damaged), rows != NULL unless count == 0, and every row valid: an
 * absolute pattern shorter than PATH_MAX, a 128-hex-character digest and
 * a non-negative updated_at.  Arguments are validated before any row is
 * touched.  Returns 0 on success, -1 on any invalid argument or write
 * failure.  rows may be NULL when count == 0.
 */
int pin_write_file(const char *filepath, const PinRecord *rows, int count);

/*
 * Load the pin table from 'filepath', always replacing the whole table
 * on success (startup and every SIGHUP reload).  Pass NULL or "" to use
 * the current state file path: the PIN_STATE_FILE default or the
 * pin_set_state_file() override.  Thin wrapper over pin_load_file()
 * staged into the module table: a failure sets pin_damaged() == 1 and
 * keeps the previously loaded table untrusted (never a silent reset to
 * an empty table).
 *
 * Returns 0 when the file was loaded or does not exist (ENOENT yields an
 * empty table with pin_damaged() == 0 - normal first use).  Returns -1
 * for any other open error and for every structural or value anomaly.
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
 * overwrites a damaged file), or when the serialize/write fails.  On a
 * failure the live table is restored to its pre-store state so memory
 * and disk stay consistent (an evicted pin whose file still holds it
 * would otherwise silently re-TOFU); a LOG_WARNING is emitted and the
 * next successful store or a restart rewrites the state.
 */
int pin_store(const char *pattern, const char *sha512);

/*
 * Remove the pin whose pattern-derived ID (ruleid_pin(): the first 16
 * hex characters of SHA-512 over the pattern) starts with 'id'.  'id'
 * must be an unambiguous 8..16-character lower-case hex prefix; the full
 * 16-character ID is accepted.  Returns 1 when a pin was removed and the
 * file rewritten, 0 when no pin matches, -2 when the prefix matches more
 * than one pin (nothing is removed), and -1 for invalid arguments, a
 * damaged table, or a failed serialize/write.
 *
 * On a write failure the pre-removal table is restored in memory (same
 * guarantee as pin_store()) so memory and disk stay consistent.  A
 * damaged file is never overwritten; repair it and reload first.
 */
int pin_remove_by_id(const char *id);

/*
 * Empty the daemon table and persist the empty table atomically.
 * Returns 0 on success; -1 when the table is damaged (repair the file
 * and reload first - pin_clear never overwrites a damaged file) or when
 * the write fails.  On a write failure the pre-clear table is restored
 * in memory.  Clearing an already-empty table still writes the file.
 */
int pin_clear(void);

/*
 * Override the state file path used by pin_store() (and by pin_load()
 * when passed NULL).  NULL or "" restores the PIN_STATE_FILE default.
 * Paths that do not fit are rejected with a LOG_ERR and leave the
 * previous path in effect.  Tests point this at a temp directory.
 */
void pin_set_state_file(const char *path);

#endif
