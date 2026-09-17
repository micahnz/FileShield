#include "ruleid.h"

#include "sha512.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Rule IDs are derived from a canonical identity buffer assembled here:
 * every field is hashed as a C string, adjacent fields separated by one
 * NUL, and the digest covers the exact byte count (sha512_buf), so the
 * separators are part of the identity.  A field can never be mistaken for
 * another field's content because the daemon's strings are NUL-free.
 */

/* Upper bound on collected fields: 5 fixed + 2 per chain level + created
 * + nonce. */
#define RULEID_MAX_FIELDS (2 * PERSIST_CHAIN_MAX + 7)

typedef struct
{
    const char *fields[RULEID_MAX_FIELDS];
    int count;
    char depth_buf[16];
    char created_buf[32];
} IdentityFields;

/*
 * Overflow-checked length accumulator: the canonical buffer is sized from
 * caller-supplied field lengths, and field sizes are not assumed here.
 */
static int size_add(size_t *total, size_t add)
{
    if (add > SIZE_MAX - *total)
        return -1;
    *total += add;
    return 0;
}

/* Decimal formatting for the numeric identity fields: a truncated field
 * would silently change every ID, so overflow is an error, not a clamp. */
static int format_int_field(int value, char *out, size_t outsz)
{
    int n = snprintf(out, outsz, "%d", value);
    return (n < 0 || (size_t)n >= outsz) ? -1 : 0;
}

static int format_long_field(long value, char *out, size_t outsz)
{
    int n = snprintf(out, outsz, "%ld", value);
    return (n < 0 || (size_t)n >= outsz) ? -1 : 0;
}

/*
 * Collect the canonical field sequence in hash order.  Returns -1 on an
 * invalid identity (NULL required field, chain_depth out of range, NULL
 * chain entry below the depth).
 */
static int identity_collect(const RuleIdentity *id, const char *nonce,
                            IdentityFields *fields)
{
    if (!id || !fields)
        return -1;
    if (id->chain_depth < 0 || id->chain_depth > PERSIST_CHAIN_MAX)
        return -1;
    if (!id->binary || !id->binary_sha512 || !id->target_path ||
        !id->cmdline_sha512)
        return -1;
    if (format_int_field(id->chain_depth, fields->depth_buf,
                         sizeof(fields->depth_buf)) < 0 ||
        format_long_field(id->created_at, fields->created_buf,
                          sizeof(fields->created_buf)) < 0)
        return -1;

    fields->count = 0;
    fields->fields[fields->count++] = id->binary;
    fields->fields[fields->count++] = id->binary_sha512;
    fields->fields[fields->count++] = id->target_path;
    fields->fields[fields->count++] = id->cmdline_sha512;
    fields->fields[fields->count++] = fields->depth_buf;

    for (int i = 0; i < id->chain_depth; i++)
    {
        if (!id->chain_comm[i] || !id->chain_sha512[i])
            return -1;
        fields->fields[fields->count++] = id->chain_comm[i];
        fields->fields[fields->count++] = id->chain_sha512[i];
    }

    fields->fields[fields->count++] = fields->created_buf;
    if (nonce)
        fields->fields[fields->count++] = nonce;
    return 0;
}

/*
 * Hash the canonical identity, optionally followed by the nonce field.
 * Returns 0 on success; -1 on invalid arguments or allocation failure.
 */
static int identity_hash(const RuleIdentity *id, const char *nonce,
                         char out[RULEID_HEX_LEN + 1])
{
    if (!out)
        return -1;

    IdentityFields fields;
    if (identity_collect(id, nonce, &fields) < 0)
        return -1;

    size_t total = 0;
    for (int i = 0; i < fields.count; i++)
    {
        if (size_add(&total, strlen(fields.fields[i])) < 0)
            return -1;
    }
    /* One NUL between adjacent fields plus the buffer terminator. */
    if (size_add(&total, (size_t)fields.count) < 0)
        return -1;

    char *buf = malloc(total);
    if (!buf)
        return -1;

    size_t pos = 0;
    for (int i = 0; i < fields.count; i++)
    {
        if (i > 0)
            buf[pos++] = '\0';
        size_t len = strlen(fields.fields[i]);
        memcpy(buf + pos, fields.fields[i], len);
        pos += len;
    }
    buf[pos] = '\0';

    char full[129];
    int rc = sha512_buf(buf, pos, full);
    free(buf);
    if (rc < 0)
        return -1;

    memcpy(out, full, RULEID_HEX_LEN);
    out[RULEID_HEX_LEN] = '\0';
    return 0;
}

static int id_list_contains(const char *const *ids, int count, const char *id)
{
    for (int i = 0; i < count; i++)
    {
        if (strcmp(ids[i], id) == 0)
            return 1;
    }
    return 0;
}

int ruleid_make(const RuleIdentity *id, unsigned nonce,
                char out[RULEID_HEX_LEN + 1])
{
    if (nonce == 0)
        return identity_hash(id, NULL, out);

    /* The nonce is a full decimal field; an unsigned cannot overflow the
     * 32-byte scratch, but keep the check so a format change cannot
     * silently truncate the one field that guarantees uniqueness. */
    char nonce_field[32];
    int n = snprintf(nonce_field, sizeof(nonce_field), "n=%u", nonce);
    if (n < 0 || (size_t)n >= sizeof(nonce_field))
        return -1;
    return identity_hash(id, nonce_field, out);
}

int ruleid_make_unique(const RuleIdentity *id, const char *const *existing_ids,
                       int existing_count, char out[RULEID_HEX_LEN + 1])
{
    if (!id || !out || existing_count < 0)
        return -1;
    if (existing_count > 0 && !existing_ids)
        return -1;
    for (int i = 0; i < existing_count; i++)
    {
        if (!existing_ids[i])
            return -1;
    }

    for (unsigned nonce = 0; nonce < RULEID_MAX_ATTEMPTS; nonce++)
    {
        if (ruleid_make(id, nonce, out) < 0)
            return -1;
        if (!id_list_contains(existing_ids, existing_count, out))
            return 0;
    }
    return -1; /* bound exhausted: fail closed, the caller re-prompts */
}

int ruleid_pin(const char *pattern, char out[RULEID_HEX_LEN + 1])
{
    if (!pattern || !out)
        return -1;

    char full[129];
    if (sha512_string(pattern, full) < 0)
        return -1;

    memcpy(out, full, RULEID_HEX_LEN);
    out[RULEID_HEX_LEN] = '\0';
    return 0;
}

static int is_hex_lower(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

/* A stored ID is exactly the format ruleid_make() emits; anything else is
 * damaged state and must never take part in a lookup. */
static int valid_stored_id(const char *id)
{
    if (!id || strlen(id) != RULEID_HEX_LEN)
        return 0;
    for (int i = 0; i < RULEID_HEX_LEN; i++)
    {
        if (!is_hex_lower(id[i]))
            return 0;
    }
    return 1;
}

/*
 * Validate a user-supplied lookup prefix and return its length.  The
 * accepted alphabet is the stored one (lower-case hex): accepting mixed
 * case would create two spellings of one ID without helping the common
 * case, where the prefix is copied from the CLI's own output.
 */
static int lookup_prefix_len(const char *input, size_t *len_out)
{
    if (!input)
        return -1;

    size_t n = strlen(input);
    if (n < RULEID_MIN_PREFIX || n > RULEID_HEX_LEN)
        return -1;
    for (size_t i = 0; i < n; i++)
    {
        if (!is_hex_lower(input[i]))
            return -1;
    }
    *len_out = n;
    return 0;
}

int ruleid_prefix_match(const char *stored_id, const char *input)
{
    size_t n;

    if (!stored_id || !input)
        return -1;
    if (!valid_stored_id(stored_id))
        return -1;
    if (lookup_prefix_len(input, &n) < 0)
        return -1;
    return memcmp(stored_id, input, n) == 0 ? 1 : 0;
}

int ruleid_find(const char *const *ids, int count, const char *input,
                int *ambiguous_out)
{
    size_t n;
    int found = -1;

    if (ambiguous_out)
        *ambiguous_out = 0;
    if (count < 0)
        return -1;
    if (count > 0 && !ids)
        return -1;
    if (lookup_prefix_len(input, &n) < 0)
        return -1;

    for (int i = 0; i < count; i++)
    {
        if (!valid_stored_id(ids[i]))
            return -1;
        if (memcmp(ids[i], input, n) == 0)
        {
            if (found >= 0)
            {
                if (ambiguous_out)
                    *ambiguous_out = 1;
                return -1;
            }
            found = i;
        }
    }
    return found;
}
