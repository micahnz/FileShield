/*
 * pin.c - hash pins for [allowlist] rules (see pin.h for the contract).
 *
 * The module keeps a bounded in-memory table and mirrors it to a strict,
 * atomically written JSON file.  Parsing fails closed: one anomaly
 * anywhere in an existing file marks the whole file damaged instead of
 * silently dropping entries, because dropping one would re-TOFU its rule.
 */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include "pin.h"
#include "persist.h"
#include "utils.h"

/*
 * A pattern is at most PATH_MAX-1 bytes and persist_json_escape() may
 * encode one byte as six (\uXXXX), so one serialized line can reach
 * 6*PATH_MAX plus the field wrapper.  The parser needs line and value
 * buffers of that size; the writer an escaped scratch buffer.
 */
#define PIN_LINE_MAX (PATH_MAX * 6 + 256)
#define PIN_ESCAPED_MAX (PATH_MAX * 6 + 8)

typedef struct
{
    char pattern[PATH_MAX];
    char sha512[129];
    time_t updated_at;
    unsigned long seq; /* store order: updated_at tie-break */
} PinEntry;

/* One table row plus "was this key seen in the current entry" flags. */
typedef struct
{
    PinEntry pin;
    int have_pattern;
    int have_sha512;
    int have_updated_at;
} PinDraft;

static PinEntry g_pins[PIN_MAX];
static int g_pin_count;
static int g_pin_damaged;
static unsigned long g_pin_seq;
static char g_state_file[PATH_MAX] = PIN_STATE_FILE;

/*
 * A damaged file must not disturb the loaded table: parse into staging
 * and commit only after the whole file validated cleanly.
 */
static PinDraft g_stage[PIN_MAX];

/* Exactly 128 hex characters: sha512sum's canonical output form. */
static int is_valid_sha512(const char *s)
{
    size_t i;

    if (!s || strlen(s) != 128)
        return 0;
    for (i = 0; i < 128; i++)
    {
        if (!isxdigit((unsigned char)s[i]))
            return 0;
    }
    return 1;
}

/* Pin keys are the canonical absolute binary patterns from config.c. */
static int is_valid_pattern(const char *p)
{
    return p && p[0] == '/' && strlen(p) < PATH_MAX;
}

/*
 * Parse one '"key": <long>' numeric pair (strict: only whitespace and an
 * optional trailing comma may follow the number).  Returns 1 with
 * *key_out and *out populated when the line is a well-formed numeric
 * field, 0 otherwise.
 */
static int parse_numeric_field(const char *line, char *key_out,
                               size_t keysz, long *out)
{
    char key[256];
    const char *rest;
    char *end;
    long value;
    size_t klen;
    int pos = 0;

    if (sscanf(line, " \"%255[^\"]\": %n", key, &pos) != 1)
        return 0;

    /* strtol (not scanf %ld): out-of-range values must be rejected, not
     * undefined.  A hand-edited file is exactly the damaged-file case. */
    rest = line + pos;
    errno = 0;
    value = strtol(rest, &end, 10);
    if (end == rest || errno == ERANGE)
        return 0;

    rest = end;
    while (*rest == ' ' || *rest == '\t')
        rest++;
    if (*rest == ',')
        rest++;
    while (*rest == ' ' || *rest == '\t' || *rest == '\r' || *rest == '\n')
        rest++;
    if (*rest != '\0')
        return 0;

    if (key_out && keysz > 0)
    {
        klen = strlen(key);
        if (klen >= keysz)
            klen = keysz - 1;
        memcpy(key_out, key, klen);
        key_out[klen] = '\0';
    }
    *out = value;
    return 1;
}

/*
 * Apply one decoded string field to the entry under construction.
 * Returns 0 to continue, -1 when a known key carries a bad value (the
 * whole file is then marked damaged).
 */
static int apply_string_field(PinDraft *d, const char *key, const char *value)
{
    size_t len;

    if (strcmp(key, "pattern") == 0)
    {
        len = strlen(value);
        if (!is_valid_pattern(value))
            return -1;
        memcpy(d->pin.pattern, value, len + 1);
        d->have_pattern = 1;
        return 0;
    }
    if (strcmp(key, "sha512") == 0)
    {
        if (!is_valid_sha512(value))
            return -1;
        memcpy(d->pin.sha512, value, 129); /* 128 validated chars + NUL */
        d->have_sha512 = 1;
        return 0;
    }
    if (strcmp(key, "updated_at") == 0)
        return -1; /* numeric field with a string value */

    return 0; /* unknown string key: ignore for forward compatibility */
}

int pin_load(const char *filepath)
{
    FILE *fp;
    char line[PIN_LINE_MAX];
    char key[256];
    char value[PIN_LINE_MAX];
    PinDraft *cur = NULL;
    int count = 0;
    int i;
    int saw_pins = 0;
    int closed_array = 0;
    int closed_object = 0;
    int ok = 1;
    enum
    {
        S_OUTSIDE,
        S_IN_PINS,
        S_IN_ENTRY,
        S_DONE
    } state = S_OUTSIDE;
    const char *path = (filepath && filepath[0] != '\0') ? filepath
                                                         : g_state_file;

    memset(g_stage, 0, sizeof(g_stage));

    fp = fopen(path, "r");
    if (!fp)
    {
        if (errno == ENOENT)
        {
            g_pin_count = 0;
            g_pin_damaged = 0;
            g_pin_seq = 0;
            log_msg(LOG_INFO, "pin_load: %s not present; starting with no pins",
                    path);
            return 0;
        }
        log_msg(LOG_ERR, "pin_load: open %s: %s", path, strerror(errno));
        g_pin_damaged = 1;
        return -1;
    }

    while (ok && fgets(line, sizeof(line), fp))
    {
        char *p = line;
        char *pins_key;

        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
            p++;
        if (*p == '\0' || *p == '#')
            continue;

        switch (state)
        {
        case S_OUTSIDE:
            pins_key = strstr(p, "\"pins\":");
            if (pins_key != NULL)
            {
                char *q = pins_key + 7; /* just after the "pins": key */

                saw_pins = 1;
                while (*q == ' ' || *q == '\t')
                    q++;
                if (*q != '[')
                {
                    ok = 0; /* "pins" must open the array */
                    break;
                }
                q++;
                while (*q == ' ' || *q == '\t')
                    q++;
                if (*q == ']')
                {
                    /* "pins": [] on one line; nothing may follow it. */
                    q++;
                    while (*q == ' ' || *q == '\t' || *q == '\r' ||
                           *q == '\n')
                        q++;
                    if (*q != '\0')
                        ok = 0;
                    else
                        closed_array = 1;
                }
                else if (*q == '\0' || *q == '\r' || *q == '\n')
                {
                    /* Array opener alone on its line. */
                    state = S_IN_PINS;
                }
                else
                {
                    /* Content on the opener line cannot be parsed by
                     * this line-oriented reader; accepting it as an
                     * empty array would silently drop pins. */
                    ok = 0;
                }
            }
            else if (*p == '{' || *p == '"')
            {
                /* Outer object opener / unknown top-level key. */
            }
            else if (*p == '}')
            {
                closed_object = 1;
                state = S_DONE;
            }
            else
            {
                ok = 0; /* structural anomaly */
            }
            break;

        case S_IN_PINS:
            if (*p == '[')
            {
                /* Array opener on its own line. */
                char *q = p + 1;
                while (*q == ' ' || *q == '\t')
                    q++;
                if (*q != '\0' && *q != '\r' && *q != '\n')
                    ok = 0; /* content on the opener line is unsupported */
            }
            else if (*p == '{')
            {
                if (count >= PIN_MAX || strchr(p, '}') != NULL)
                {
                    ok = 0; /* too many entries / unsupported one-liner */
                    break;
                }
                cur = &g_stage[count];
                memset(cur, 0, sizeof(*cur));
                state = S_IN_ENTRY;
            }
            else if (*p == ']')
            {
                char *q = p + 1;

                while (*q == ' ' || *q == '\t')
                    q++;
                if (*q != '\0' && *q != '\r' && *q != '\n')
                {
                    ok = 0; /* junk after the array close */
                    break;
                }
                closed_array = 1;
                state = S_OUTSIDE;
            }
            else
            {
                ok = 0;
            }
            break;

        case S_IN_ENTRY:
            if (cur == NULL)
            {
                ok = 0;
                break;
            }
            if (*p == '}')
            {
                if (!cur->have_pattern || !cur->have_sha512 ||
                    !cur->have_updated_at)
                {
                    ok = 0; /* incomplete entry: never dropped silently */
                    break;
                }
                cur->pin.seq = (unsigned long)count;
                count++;
                cur = NULL;
                state = S_IN_PINS;
                break;
            }

            if (persist_json_extract_string(p, key, sizeof(key), value,
                                            sizeof(value)))
            {
                if (apply_string_field(cur, key, value) < 0)
                    ok = 0;
            }
            else
            {
                long num;

                if (!parse_numeric_field(p, key, sizeof(key), &num))
                {
                    ok = 0; /* neither a string field nor a number */
                }
                else if (strcmp(key, "updated_at") == 0)
                {
                    if (num < 0)
                    {
                        ok = 0;
                    }
                    else
                    {
                        cur->pin.updated_at = (time_t)num;
                        cur->have_updated_at = 1;
                    }
                }
                else if (strcmp(key, "pattern") == 0 ||
                         strcmp(key, "sha512") == 0)
                {
                    ok = 0; /* known string key with a numeric value */
                }
                /* else: unknown numeric key, ignored. */
            }
            break;

        case S_DONE:
            ok = 0; /* nothing may follow the outer object */
            break;
        }
    }

    if (ferror(fp))
        ok = 0;
    fclose(fp);

    if (!ok || !saw_pins || !closed_array || !closed_object ||
        state == S_IN_ENTRY)
    {
        log_msg(LOG_ERR,
                "pin_load: %s is damaged; keeping the previous pin table "
                "(fail closed)", path);
        g_pin_damaged = 1;
        return -1;
    }

    for (i = 0; i < count; i++)
        g_pins[i] = g_stage[i].pin;
    g_pin_count = count;
    g_pin_seq = (unsigned long)count;
    g_pin_damaged = 0;
    log_msg(LOG_INFO, "pin_load: loaded %d pin(s) from %s", count, path);
    return 0;
}

int pin_damaged(void)
{
    return g_pin_damaged;
}

int pin_check(const char *pattern, const char *sha512, char old_out[129])
{
    int i;

    if (old_out)
        old_out[0] = '\0';

    if (g_pin_damaged)
        return PIN_CHECK_DAMAGED;
    if (!pattern || pattern[0] == '\0' || !is_valid_sha512(sha512))
        return PIN_CHECK_DAMAGED;

    for (i = 0; i < g_pin_count; i++)
    {
        if (strcmp(g_pins[i].pattern, pattern) != 0)
            continue;
        if (strcmp(g_pins[i].sha512, sha512) == 0)
            return PIN_CHECK_MATCH;
        if (old_out)
            memcpy(old_out, g_pins[i].sha512, 129);
        return PIN_CHECK_CHANGED;
    }
    return PIN_CHECK_FIRST_USE;
}

/* Grow *buf so that 'need' bytes (including the NUL) fit. */
static int sb_reserve(char **buf, size_t *cap, size_t need)
{
    char *grown;
    size_t ncap = *cap;

    if (need <= ncap)
        return 0;
    while (ncap < need)
    {
        if (ncap > SIZE_MAX / 2)
            return -1;
        ncap *= 2;
    }
    grown = realloc(*buf, ncap);
    if (!grown)
        return -1;
    *buf = grown;
    *cap = ncap;
    return 0;
}

static int sb_append_n(char **buf, size_t *cap, size_t *len,
                       const char *s, size_t n)
{
    if (sb_reserve(buf, cap, *len + n + 1) < 0)
        return -1;
    memcpy(*buf + *len, s, n);
    *len += n;
    (*buf)[*len] = '\0';
    return 0;
}

static int sb_append(char **buf, size_t *cap, size_t *len, const char *s)
{
    return sb_append_n(buf, cap, len, s, strlen(s));
}

/*
 * Serialize the live table into a freshly allocated JSON text (caller
 * frees).  Returns 0 on success, -1 on allocation failure or when a
 * pattern cannot be represented (defense in depth: load and store both
 * bound patterns to PATH_MAX-1, so this cannot happen for valid state).
 */
static int pin_serialize(char **out_text)
{
    char *buf;
    size_t cap = 4096;
    size_t len = 0;
    char escaped[PIN_ESCAPED_MAX];
    char num[32];
    int i;

    buf = malloc(cap);
    if (!buf)
        return -1;
    buf[0] = '\0';

    if (sb_append(&buf, &cap, &len, "{\n  \"pins\": [\n") < 0)
        goto fail;

    for (i = 0; i < g_pin_count; i++)
    {
        if (persist_json_escape(g_pins[i].pattern, escaped,
                                sizeof(escaped)) < 0)
        {
            log_msg(LOG_ERR, "pin_serialize: entry %d pattern does not fit", i);
            goto fail;
        }

        snprintf(num, sizeof(num), "%ld", (long)g_pins[i].updated_at);

        if (sb_append(&buf, &cap, &len, "    {\n      \"pattern\": \"") < 0 ||
            sb_append(&buf, &cap, &len, escaped) < 0 ||
            sb_append(&buf, &cap, &len, "\",\n      \"sha512\": \"") < 0 ||
            sb_append(&buf, &cap, &len, g_pins[i].sha512) < 0 ||
            sb_append(&buf, &cap, &len, "\",\n      \"updated_at\": ") < 0 ||
            sb_append(&buf, &cap, &len, num) < 0 ||
            sb_append(&buf, &cap, &len, "\n    }") < 0)
            goto fail;
        if (i + 1 < g_pin_count && sb_append(&buf, &cap, &len, ",") < 0)
            goto fail;
        if (sb_append(&buf, &cap, &len, "\n") < 0)
            goto fail;
    }

    if (sb_append(&buf, &cap, &len, "  ]\n}\n") < 0)
        goto fail;

    *out_text = buf;
    return 0;

fail:
    free(buf);
    return -1;
}

int pin_store(const char *pattern, const char *sha512)
{
    int i;
    int idx = -1;
    char *text = NULL;

    if (!is_valid_pattern(pattern) || !is_valid_sha512(sha512))
    {
        log_msg(LOG_WARNING, "pin_store: invalid pattern or sha512 argument");
        return -1;
    }

    if (g_pin_damaged)
    {
        log_msg(LOG_ERR, "pin_store: pin table is damaged; refusing to "
                         "overwrite %s (repair the file and reload first)",
                g_state_file);
        return -1;
    }

    for (i = 0; i < g_pin_count; i++)
    {
        if (strcmp(g_pins[i].pattern, pattern) == 0)
        {
            idx = i;
            break;
        }
    }

    if (idx < 0 && g_pin_count < PIN_MAX)
        idx = g_pin_count++;
    if (idx < 0)
    {
        /* Table full: evict the smallest updated_at; ties go to the
         * oldest store (a refresh counts as a store). */
        idx = 0;
        for (i = 1; i < g_pin_count; i++)
        {
            if (g_pins[i].updated_at < g_pins[idx].updated_at ||
                (g_pins[i].updated_at == g_pins[idx].updated_at &&
                 g_pins[i].seq < g_pins[idx].seq))
                idx = i;
        }
        log_msg(LOG_INFO, "pin_store: table full; evicting pin %s",
                g_pins[idx].pattern);
    }

    memcpy(g_pins[idx].pattern, pattern, strlen(pattern) + 1);
    memcpy(g_pins[idx].sha512, sha512, 129);
    g_pins[idx].updated_at = time(NULL);
    g_pins[idx].seq = g_pin_seq++;

    if (pin_serialize(&text) < 0)
    {
        log_msg(LOG_WARNING, "pin_store: could not serialize the pin table");
        return -1;
    }
    if (persist_write_text(g_state_file, text) < 0)
    {
        free(text);
        log_msg(LOG_WARNING, "pin_store: could not write %s; the pin is "
                             "kept in memory only", g_state_file);
        return -1;
    }
    free(text);
    log_msg(LOG_INFO, "pin_store: wrote %d pin(s) to %s", g_pin_count,
            g_state_file);
    return 0;
}

void pin_set_state_file(const char *path)
{
    if (!path || path[0] == '\0')
    {
        memcpy(g_state_file, PIN_STATE_FILE, sizeof(PIN_STATE_FILE));
        return;
    }
    if (strlen(path) >= sizeof(g_state_file))
    {
        log_msg(LOG_ERR, "pin_set_state_file: path too long");
        return;
    }
    memcpy(g_state_file, path, strlen(path) + 1);
}
