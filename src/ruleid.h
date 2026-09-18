#ifndef FILESHIELD_RULEID_H
#define FILESHIELD_RULEID_H

#include "persist.h"

/*
 * Rule IDs: compact, stable identifiers for dynamic allow/deny rules and
 * [allowlist] hash pins.
 *
 * A rule ID is the first RULEID_HEX_LEN (16) lower-case hex characters of
 * the SHA-512 digest of a canonical NUL-separated identity: the binary
 * path, binary SHA-512, target path, command-line SHA-512, decimal chain
 * depth, each chain level's comm and SHA-512 (in order), then the decimal
 * creation time.  Fields are C strings hashed with their length supplied
 * to sha512_buf(), so a field boundary can never be confused with field
 * content -- daemon strings never contain NUL bytes.
 *
 * The same identity always hashes to the same ID.  Uniqueness is a
 * property of the caller's list, not of the digest: ruleid_make_unique()
 * tries the identity itself and, when that ID is already taken, appends a
 * nonce field ("n=<n>", NUL-separated like every other field) and
 * re-hashes until the ID is absent from the list.  A non-zero nonce is
 * part of the hashed bytes, so an ID is stable for a given identity and
 * nonce; see ruleid_make().
 *
 * Pin IDs are derived from the [allowlist] rule's canonical binary
 * pattern instead (the pin table stores no ID), computed on demand.
 *
 * All functions are pure: no I/O, no globals, no logging, no caller data
 * is modified.  Invalid arguments (NULL fields, chain_depth outside
 * 0..PERSIST_CHAIN_MAX, NULL chain entries below the depth) return -1 and
 * never crash.
 */

#define RULEID_HEX_LEN 16       /* stored ID width: lower-case hex chars */
#define RULEID_MIN_PREFIX 8     /* shortest accepted lookup prefix */
#define RULEID_MAX_ATTEMPTS 256 /* collision retries before failing closed */

/*
 * Identity of one rule.  All pointers are borrowed for the call only.
 * chain_comm[]/chain_sha512[] below chain_depth are hashed in order and
 * must be non-NULL; entries at or above chain_depth are ignored, so a
 * caller can hash a shallower chain without clearing stale tail entries.
 */
typedef struct
{
    const char *binary;
    const char *binary_sha512;
    const char *target_path;
    const char *cmdline_sha512;
    int chain_depth;
    const char *chain_comm[PERSIST_CHAIN_MAX];
    const char *chain_sha512[PERSIST_CHAIN_MAX];
    long created_at;
} RuleIdentity;

/*
 * Hash one identity into out[RULEID_HEX_LEN + 1] (16 lower-case hex plus
 * NUL).  nonce 0 selects the plain canonical identity; a non-zero nonce
 * appends the field "n=<nonce>" before hashing and is how collisions are
 * resolved.  Returns 0 on success, -1 on invalid arguments or allocation
 * failure; out is left untouched on failure.
 */
int ruleid_make(const RuleIdentity *id, unsigned nonce,
                char out[RULEID_HEX_LEN + 1]);

/*
 * ruleid_make() plus uniqueness: returns the plain ID when it differs
 * from every existing_ids[i], otherwise the first nonce variant
 * (1, 2, ... up to RULEID_MAX_ATTEMPTS retries) that does.  existing_ids
 * may be NULL when existing_count is 0; every entry must be non-NULL.
 * Returns 0 on success, -1 on invalid arguments, allocation failure, or
 * when the retry bound is exhausted (fail closed).
 */
int ruleid_make_unique(const RuleIdentity *id, const char *const *existing_ids,
                       int existing_count, char out[RULEID_HEX_LEN + 1]);

/*
 * Pin ID: first RULEID_HEX_LEN hex characters of SHA-512(pattern),
 * computed on demand (the pin table stores no ID).  Returns 0 on success,
 * -1 on invalid arguments.
 */
int ruleid_pin(const char *pattern, char out[RULEID_HEX_LEN + 1]);

/*
 * Prefix lookup against one stored ID: 1 when input is a valid prefix of
 * stored_id, 0 when input is valid but does not match, -1 when either
 * argument is invalid.  stored_id must be exactly RULEID_HEX_LEN
 * lower-case hex characters.  input must be RULEID_MIN_PREFIX..
 * RULEID_HEX_LEN lower-case hex characters (the full 16 is allowed);
 * anything shorter, longer or non-hex is an error, never a match (fail
 * closed).
 */
int ruleid_prefix_match(const char *stored_id, const char *input);

/*
 * Find input among count stored IDs.  Returns the matching index, or -1
 * when there is no match, the input is invalid, or the prefix is
 * ambiguous.  When ambiguous_out is non-NULL it is set to 1 only for an
 * ambiguous prefix (multiple matches), 0 otherwise, so the caller can
 * tell "not found" from "too many candidates" without another pass.
 * Malformed or NULL list entries fail the lookup (a damaged list is an
 * error, not a silent skip).
 */
int ruleid_find(const char *const *ids, int count, const char *input,
                int *ambiguous_out);

#endif /* FILESHIELD_RULEID_H */
