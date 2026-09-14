#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>
#include <syslog.h>

#include "persist.h"
#include "utils.h"

/* Ensure the state directory exists with secure permissions (0700, root-only). */
static int ensure_state_dir(const char *dirpath)
{
    struct stat st;

    /* lstat: never follow a symlink placed at the state directory path. */
    if (lstat(dirpath, &st) == 0)
    {
        if (S_ISLNK(st.st_mode))
        {
            log_msg(LOG_ERR, "%s is a symlink; refusing to use it", dirpath);
            return -1;
        }
        if (!S_ISDIR(st.st_mode))
        {
            log_msg(LOG_ERR, "%s exists but is not a directory", dirpath);
            return -1;
        }
        if (geteuid() == 0 && st.st_uid != 0)
        {
            log_msg(LOG_ERR, "%s is not owned by root; refusing to use it",
                    dirpath);
            return -1;
        }
        if ((st.st_mode & 0777) != 0700)
        {
            if (chmod(dirpath, 0700) < 0)
                log_msg(LOG_WARNING, "chmod %s: %s", dirpath, strerror(errno));
        }
        return 0;
    }

    if (errno != ENOENT)
    {
        log_msg(LOG_ERR, "stat %s: %s", dirpath, strerror(errno));
        return -1;
    }

    if (mkdir(dirpath, 0700) < 0)
    {
        log_msg(LOG_ERR, "mkdir %s: %s", dirpath, strerror(errno));
        return -1;
    }

    return 0;
}

static int json_escape_string(const char *src, char *dst, size_t dst_size)
{
    size_t written = 0;
    unsigned char c;

    if (!src || !dst || dst_size < 1)
        return -1;

    for (; *src; src++)
    {
        c = (unsigned char)*src;

        if (written + 2 >= dst_size)
            return -1;

        if (c == '"')
        {
            dst[written++] = '\\';
            dst[written++] = '"';
        }
        else if (c == '\\')
        {
            dst[written++] = '\\';
            dst[written++] = '\\';
        }
        else if (c == '\b')
        {
            dst[written++] = '\\';
            dst[written++] = 'b';
        }
        else if (c == '\f')
        {
            dst[written++] = '\\';
            dst[written++] = 'f';
        }
        else if (c == '\n')
        {
            dst[written++] = '\\';
            dst[written++] = 'n';
        }
        else if (c == '\r')
        {
            dst[written++] = '\\';
            dst[written++] = 'r';
        }
        else if (c == '\t')
        {
            dst[written++] = '\\';
            dst[written++] = 't';
        }
        else if (c < 0x20)
        {
            if (written + 6 >= dst_size)
                return -1;
            int n = snprintf(&dst[written], dst_size - written, "\\u%04x", c);
            if (n < 0 || n >= (int)(dst_size - written))
                return -1;
            written += (size_t)n;
        }
        else
        {
            dst[written++] = c;
        }
    }

    if (written >= dst_size)
        return -1;

    dst[written] = '\0';
    return (int)written;
}

/* Bounded string copy with NUL termination. */
static void copy_field(char *dst, size_t dstsz, const char *src)
{
    size_t len;

    if (!dst || dstsz == 0)
        return;
    len = strlen(src);
    if (len >= dstsz)
        len = dstsz - 1;
    memcpy(dst, src, len);
    dst[len] = '\0';
}

/*
 * Extract a JSON string key/value pair from a single line of the form
 *   "key": "value",
 * Unescapes the value into out (bounded, always NUL-terminated) and
 * returns 1 when a string pair was found, writing the key into key_out.
 *
 * A plain %[^"] sscanf scan cannot handle escaped quotes, which command
 * lines contain routinely (`sh -c "..."`), so the value is decoded
 * escape-aware instead.  Returns 0 for numeric fields or malformed input.
 */
static int json_extract_string(const char *line, char *key_out, size_t keysz,
                               char *out, size_t outsz)
{
    char found_key[256];
    const char *p;
    size_t j = 0;

    if (!out || outsz == 0)
        return 0;
    out[0] = '\0';

    if (sscanf(line, " \"%255[^\"]\"", found_key) != 1)
        return 0;

    p = strchr(line, ':');
    if (!p)
        return 0;
    p++;
    while (*p == ' ' || *p == '\t')
        p++;
    if (*p != '"')
        return 0; /* numeric or non-string value */
    p++;

    while (*p != '\0' && *p != '"')
    {
        unsigned char c = (unsigned char)*p;

        if (c == '\\')
        {
            p++;
            if (*p == '\0')
                return 0; /* malformed trailing escape */
            switch (*p)
            {
            case '"': c = '"'; break;
            case '\\': c = '\\'; break;
            case '/': c = '/'; break;
            case 'b': c = '\b'; break;
            case 'f': c = '\f'; break;
            case 'n': c = '\n'; break;
            case 'r': c = '\r'; break;
            case 't': c = '\t'; break;
            case 'u':
            {
                unsigned int code = 0;
                if (sscanf(p + 1, "%4x", &code) != 1)
                    return 0;
                p += 4;
                if (code < 0x80)
                {
                    c = (unsigned char)code;
                }
                else
                {
                    /* Encode the code point back to UTF-8. */
                    unsigned char utf8[3];
                    int n;
                    if (code < 0x800)
                    {
                        utf8[0] = (unsigned char)(0xC0 | (code >> 6));
                        utf8[1] = (unsigned char)(0x80 | (code & 0x3F));
                        n = 2;
                    }
                    else
                    {
                        utf8[0] = (unsigned char)(0xE0 | (code >> 12));
                        utf8[1] = (unsigned char)(0x80 | ((code >> 6) & 0x3F));
                        utf8[2] = (unsigned char)(0x80 | (code & 0x3F));
                        n = 3;
                    }
                    if (j + (size_t)n >= outsz)
                        return 0; /* value does not fit */
                    for (int k = 0; k < n; k++)
                        out[j++] = (char)utf8[k];
                    p++;
                    continue;
                }
                break;
            }
            default:
                return 0; /* unknown escape sequence */
            }
        }
        else if (c < 0x20)
        {
            return 0; /* raw control character inside a JSON string */
        }

        if (j + 1 >= outsz)
            return 0; /* value does not fit */
        out[j++] = (char)c;
        p++;
    }
    if (*p != '"')
        return 0; /* unterminated value */

    out[j] = '\0';
    if (key_out && keysz > 0)
        snprintf(key_out, keysz, "%s", found_key);
    return 1;
}

int persist_load(const char *filepath, PersistEntry *out_entries, int max_entries)
{
    FILE *fp;
    char line[4096];
    PersistEntry *current = NULL;
    int count = 0;

    enum
    {
        S_OUTSIDE,
        S_IN_ENTRIES,
        S_IN_ENTRY
    } state = S_OUTSIDE;

    if (!out_entries || max_entries <= 0)
        return 0;

    memset(out_entries, 0, sizeof(*out_entries) * max_entries);

    fp = fopen(filepath, "r");
    if (!fp)
    {
        if (errno == ENOENT)
            return 0;
        log_msg(LOG_ERR, "persist_load: open %s: %s", filepath,
                strerror(errno));
        return -1;
    }

    while (fgets(line, sizeof(line), fp) && count < max_entries)
    {
        char *p = line;

        while (*p && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
            p++;

        if (!*p || *p == '#')
            continue;

        /* Detect the "entries": [ array opener. */
        if (state == S_OUTSIDE && strstr(p, "\"entries\":") != NULL)
        {
            state = S_IN_ENTRIES;
            continue;
        }

        /* Entry start: opening brace inside the entries array. */
        if (state == S_IN_ENTRIES && *p == '{')
        {
            current = &out_entries[count];
            memset(current, 0, sizeof(*current));
            state = S_IN_ENTRY;
            continue;
        }

        /* Entry end: closing brace.  Sanitise and finalise. */
        if (state == S_IN_ENTRY && *p == '}')
        {
            /* Defense in depth: never index arrays with an out-of-range
             * depth, even if a previous validation step was bypassed. */
            if (current->chain_depth < 0)
                current->chain_depth = 0;
            if (current->chain_depth > PERSIST_CHAIN_MAX)
                current->chain_depth = PERSIST_CHAIN_MAX;
            for (int k = current->chain_depth; k < PERSIST_CHAIN_MAX; k++)
            {
                current->chain_comm[k][0] = '\0';
                current->chain_sha512[k][0] = '\0';
            }
            count++;
            current = NULL;
            state = S_IN_ENTRIES;
            continue;
        }

        /* End of entries array or outer closing brace. */
        if ((state == S_IN_ENTRIES && (*p == ']' || *p == '}')) ||
            (state == S_OUTSIDE && *p == '}'))
        {
            if (state == S_IN_ENTRIES)
                state = S_OUTSIDE;
            continue;
        }

        if (state != S_IN_ENTRY || !current)
            continue;

        /* Parse key-value pairs.  String values are decoded escape-aware
         * (command lines routinely contain quotes); numeric fields fall
         * through to sscanf.  Patterns intentionally omit the trailing
         * comma so they match both "value", and "value". */
        char key_buf[256], val_buf[4096];
        if (json_extract_string(p, key_buf, sizeof(key_buf), val_buf,
                                sizeof(val_buf)))
        {
            int idx;
            if (strcmp(key_buf, "binary") == 0)
                copy_field(current->binary, sizeof(current->binary), val_buf);
            else if (strcmp(key_buf, "binary_sha512") == 0)
                copy_field(current->binary_sha512,
                           sizeof(current->binary_sha512), val_buf);
            else if (strcmp(key_buf, "target_path") == 0)
                copy_field(current->target_path,
                           sizeof(current->target_path), val_buf);
            else if (strcmp(key_buf, "cmdline") == 0)
                copy_field(current->cmdline, sizeof(current->cmdline), val_buf);
            else if (strcmp(key_buf, "cmdline_sha512") == 0)
                copy_field(current->cmdline_sha512,
                           sizeof(current->cmdline_sha512), val_buf);
            else if (sscanf(key_buf, "chain_comm[%d]", &idx) == 1 &&
                     idx >= 0 && idx < PERSIST_CHAIN_MAX)
                copy_field(current->chain_comm[idx],
                           sizeof(current->chain_comm[idx]), val_buf);
            else if (sscanf(key_buf, "chain_sha512[%d]", &idx) == 1 &&
                     idx >= 0 && idx < PERSIST_CHAIN_MAX)
                copy_field(current->chain_sha512[idx],
                           sizeof(current->chain_sha512[idx]), val_buf);
        }
        else
        {
            int tmp_int;
            long created_tmp;
            if (sscanf(p, " \"%255[^\"]\": %d", key_buf, &tmp_int) == 2 &&
                strcmp(key_buf, "chain_depth") == 0)
            {
                /* chain_depth is used as an array bound: reject anything
                 * outside [0, PERSIST_CHAIN_MAX] at the parse boundary. */
                if (tmp_int >= 0 && tmp_int <= PERSIST_CHAIN_MAX)
                {
                    current->chain_depth = tmp_int;
                }
                else
                {
                    log_msg(LOG_WARNING,
                            "persist_load: chain_depth %d out of range [0,%d], clamping",
                            tmp_int, PERSIST_CHAIN_MAX);
                    current->chain_depth = tmp_int < 0 ? 0 : PERSIST_CHAIN_MAX;
                }
            }
            else if (sscanf(p, " \"%255[^\"]\": %ld", key_buf, &created_tmp) == 2 &&
                     strcmp(key_buf, "created_at") == 0)
            {
                current->created_at = (time_t)created_tmp;
            }
        }
    }

    fclose(fp);
    log_msg(LOG_INFO, "persist_load: loaded %d entries from %s", count, filepath);
    return count;
}

int persist_save(const char *filepath, const PersistEntry *entries, int count)
{
    FILE *fp;
    int i, j;
    char tmp_file[PATH_MAX];
    char escaped[4096];

    if (!entries || count < 0 || count > PERSIST_MAX_ENTRIES)
        return -1;

    /* Derive the parent directory from filepath and ensure it exists. */
    {
        char dirpath[PATH_MAX];
        snprintf(dirpath, sizeof(dirpath), "%s", filepath);
        char *slash = strrchr(dirpath, '/');
        if (slash && slash != dirpath)
        {
            *slash = '\0';
            if (ensure_state_dir(dirpath) < 0)
                return -1;
        }
    }

    snprintf(tmp_file, sizeof(tmp_file), "%s.tmp.%d", filepath, (int)getpid());

    /* Create the temp file with restrictive permissions from the start
     * (never world-readable, never following a planted symlink). */
    int fd = open(tmp_file,
                  O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0 && errno == EEXIST)
    {
        /* Stale temp file from a previous crash: remove and retry once. */
        unlink(tmp_file);
        fd = open(tmp_file,
                  O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    }
    if (fd < 0)
    {
        log_msg(LOG_ERR, "persist_save: open %s: %s", tmp_file, strerror(errno));
        return -1;
    }

    fp = fdopen(fd, "w");
    if (!fp)
    {
        log_msg(LOG_ERR, "persist_save: fdopen %s: %s", tmp_file, strerror(errno));
        close(fd);
        unlink(tmp_file);
        return -1;
    }

    fprintf(fp, "{\n");
    fprintf(fp, "  \"entries\": [\n");

    for (i = 0; i < count; i++)
    {
        const PersistEntry *e = &entries[i];

        fprintf(fp, "    {\n");

        if (json_escape_string(e->binary, escaped, sizeof(escaped)) > 0)
            fprintf(fp, "      \"binary\": \"%s\",\n", escaped);
        else
            fprintf(fp, "      \"binary\": \"\",\n");

        if (json_escape_string(e->binary_sha512, escaped, sizeof(escaped)) > 0)
            fprintf(fp, "      \"binary_sha512\": \"%s\",\n", escaped);
        else
            fprintf(fp, "      \"binary_sha512\": \"\",\n");

        if (json_escape_string(e->target_path, escaped, sizeof(escaped)) > 0)
            fprintf(fp, "      \"target_path\": \"%s\",\n", escaped);
        else
            fprintf(fp, "      \"target_path\": \"\",\n");

        if (json_escape_string(e->cmdline, escaped, sizeof(escaped)) > 0)
            fprintf(fp, "      \"cmdline\": \"%s\",\n", escaped);
        else
            fprintf(fp, "      \"cmdline\": \"\",\n");

        if (json_escape_string(e->cmdline_sha512, escaped, sizeof(escaped)) > 0)
            fprintf(fp, "      \"cmdline_sha512\": \"%s\",\n", escaped);
        else
            fprintf(fp, "      \"cmdline_sha512\": \"\",\n");

        fprintf(fp, "      \"chain_depth\": %d,\n", e->chain_depth);
        fprintf(fp, "      \"created_at\": %ld,\n", (long)e->created_at);

        /* chain_comm always gets a trailing comma: chain_sha512 fields follow. */
        for (j = 0; j < PERSIST_CHAIN_MAX; j++)
        {
            if (json_escape_string(e->chain_comm[j], escaped, sizeof(escaped)) > 0)
                fprintf(fp, "      \"chain_comm[%d]\": \"%s\",\n", j, escaped);
            else
                fprintf(fp, "      \"chain_comm[%d]\": \"\",\n", j);
        }

        /* Last chain_sha512 field has no trailing comma (closes the object). */
        for (j = 0; j < PERSIST_CHAIN_MAX; j++)
        {
            if (json_escape_string(e->chain_sha512[j], escaped, sizeof(escaped)) > 0)
                fprintf(fp, "      \"chain_sha512[%d]\": \"%s\"%s\n", j, escaped,
                        j < PERSIST_CHAIN_MAX - 1 ? "," : "");
            else
                fprintf(fp, "      \"chain_sha512[%d]\": \"\"%s\n", j,
                        j < PERSIST_CHAIN_MAX - 1 ? "," : "");
        }

        fprintf(fp, "    }%s\n", i < count - 1 ? "," : "");
    }

    fprintf(fp, "  ]\n");
    fprintf(fp, "}\n");

    if (fflush(fp) < 0)
    {
        log_msg(LOG_ERR, "persist_save: flush %s: %s", tmp_file, strerror(errno));
        fclose(fp);
        unlink(tmp_file);
        return -1;
    }
    if (fsync(fileno(fp)) < 0)
        log_msg(LOG_WARNING, "persist_save: fsync %s: %s", tmp_file, strerror(errno));

    if (fclose(fp) < 0)
    {
        log_msg(LOG_ERR, "persist_save: close %s: %s", tmp_file, strerror(errno));
        unlink(tmp_file);
        return -1;
    }

    if (rename(tmp_file, filepath) < 0)
    {
        log_msg(LOG_ERR, "persist_save: rename %s -> %s: %s", tmp_file, filepath,
                strerror(errno));
        unlink(tmp_file);
        return -1;
    }

    log_msg(LOG_INFO, "persist_save: saved %d entries to %s", count, filepath);
    return 0;
}

int persist_delete(const char *filepath)
{
    if (unlink(filepath) < 0 && errno != ENOENT)
    {
        log_msg(LOG_ERR, "persist_delete: unlink %s: %s", filepath,
                strerror(errno));
        return -1;
    }
    return 0;
}

int persist_remove_key(const char *filepath, const char *binary,
                       const char *binary_sha512, const char *target_path)
{
    PersistEntry *entries;
    int count;
    int removed = 0;
    int ret;

    if (!filepath || !binary || !binary_sha512)
        return -1;

    /* Heap-allocated: PersistEntry is ~9 KB, and 256 of them would need a
     * ~2.3 MB stack frame. */
    entries = calloc(PERSIST_MAX_ENTRIES, sizeof(PersistEntry));
    if (!entries)
        return -1;

    count = persist_load(filepath, entries, PERSIST_MAX_ENTRIES);
    if (count < 0)
    {
        free(entries);
        return -1;
    }

    for (int i = 0; i < count;)
    {
        int matches = strcmp(entries[i].binary, binary) == 0 &&
                      strcmp(entries[i].binary_sha512, binary_sha512) == 0;

        /* With a target argument, only that exact file is removed. */
        if (matches && target_path &&
            strcmp(entries[i].target_path, target_path) != 0)
            matches = 0;

        if (matches)
        {
            memmove(&entries[i], &entries[i + 1],
                    (size_t)(count - i - 1) * sizeof(PersistEntry));
            count--;
            removed = 1;
            continue;
        }
        i++;
    }

    if (!removed)
    {
        free(entries);
        return 1;
    }

    if (count == 0)
    {
        ret = persist_delete(filepath) == 0 ? 0 : -1;
        free(entries);
        return ret;
    }

    ret = persist_save(filepath, entries, count);
    free(entries);
    return ret;
}
