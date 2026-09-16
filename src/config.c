#include "config.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

Config *g_config = NULL;

static char *trim(char *s)
{
    while (*s == ' ' || *s == '\t')
        s++;
    size_t len = strlen(s);
    if (len == 0)
        return s;
    char *end = s + len - 1;
    while (end >= s && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r'))
        end--;
    *(end + 1) = '\0';
    return s;
}

/*
 * canonicalize_path: resolve symlinks so path comparisons against
 * /proc/self/fd/N paths (which are always canonical) cannot be bypassed
 * by a symlinked home/config directory.  If the path does not exist yet,
 * resolve its parent and keep the basename.
 */
static void canonicalize_path(const char *in, char *out, size_t outsz)
{
    char buf[PATH_MAX];
    size_t len;
    char *resolved;

    snprintf(buf, sizeof(buf), "%s", in);
    len = strlen(buf);
    while (len > 1 && buf[len - 1] == '/')
        buf[--len] = '\0';

    resolved = realpath(buf, NULL);
    if (resolved)
    {
        snprintf(out, outsz, "%s", resolved);
        free(resolved);
        return;
    }

    char *slash = strrchr(buf, '/');
    if (slash && slash != buf)
    {
        *slash = '\0';
        resolved = realpath(buf, NULL);
        if (resolved)
        {
            if (resolved[1] == '\0')
                snprintf(out, outsz, "/%s", slash + 1);
            else
                snprintf(out, outsz, "%s/%s", resolved, slash + 1);
            free(resolved);
            return;
        }
    }

    snprintf(out, outsz, "%s", in);
}

/*
 * rule_pattern_set: canonicalize one path-or-glob pattern into out,
 * recording whether it is a glob and the length of its wildcard-free
 * base.  Shared by [protected_paths] entries and both sides of every
 * rule, so all three accept the same syntax and fail the same way.
 *
 * Exact patterns keep the historical behavior: the whole path is
 * canonicalized.
 *
 * Glob patterns are split at the first wildcard segment.  Only the
 * wildcard-free base is canonicalized (so symlinked homes still match
 * the canonical /proc/self/fd target paths); the suffix is matched
 * verbatim by glob_match_path().  A malformed pattern — relative, no
 * static base, '..', an empty segment ("//" or a trailing slash) — is
 * rejected.  Fail closed: a typo'd pattern must never silently match
 * nothing.
 *
 * Returns 0 on success, -1 when the pattern is rejected.
 */
static int rule_pattern_set(char *out, size_t outsz, int *is_glob,
                            int *base_len, const char *raw)
{
    if (strchr(raw, '*') == NULL)
    {
        canonicalize_path(raw, out, outsz);
        *is_glob = 0;
        *base_len = (int)strlen(out);
        return 0;
    }

    if (raw[0] != '/')
    {
        log_msg(LOG_ERR, "config_load: glob pattern must be absolute: %s", raw);
        return -1;
    }

    int blen = glob_base_len(raw);
    if (blen <= 0)
    {
        log_msg(LOG_ERR, "config_load: glob pattern has no static base: %s", raw);
        return -1;
    }
    if (blen >= PATH_MAX)
    {
        log_msg(LOG_ERR, "config_load: glob base too long: %s", raw);
        return -1;
    }

    char base[PATH_MAX];
    memcpy(base, raw, (size_t)blen);
    base[blen] = '\0';

    const char *suffix = raw + blen;
    if (*suffix != '/')
    {
        log_msg(LOG_ERR, "config_load: malformed glob pattern: %s", raw);
        return -1;
    }

    /* Suffix segments must be non-empty and free of "..". */
    for (const char *p = suffix + 1;;)
    {
        const char *end = strchr(p, '/');
        size_t seglen = end ? (size_t)(end - p) : strlen(p);
        if (seglen == 0)
        {
            log_msg(LOG_ERR, "config_load: empty segment in glob pattern: %s", raw);
            return -1;
        }
        if (seglen == 2 && p[0] == '.' && p[1] == '.')
        {
            log_msg(LOG_ERR, "config_load: '..' not allowed in glob pattern: %s", raw);
            return -1;
        }
        if (!end)
            break;
        p = end + 1;
    }

    char base_canon[PATH_MAX];
    canonicalize_path(base, base_canon, sizeof(base_canon));

    size_t canon_len = strlen(base_canon);
    size_t suffix_len = strlen(suffix);

    /* An unresolvable ".." in the base yields a pattern no canonical
     * target can ever match; reject it rather than match nothing. */
    if (strstr(base_canon, "/../") != NULL ||
        (canon_len > 3 && strcmp(base_canon + canon_len - 3, "/..") == 0) ||
        strcmp(base_canon, "/..") == 0)
    {
        log_msg(LOG_ERR, "config_load: unresolvable '..' in glob base: %s", raw);
        return -1;
    }

    if (canon_len + suffix_len >= outsz)
    {
        log_msg(LOG_ERR, "config_load: glob pattern too long: %s", raw);
        return -1;
    }

    if (canon_len == 1 && base_canon[0] == '/')
    {
        memcpy(out, suffix, suffix_len + 1);
    }
    else
    {
        memcpy(out, base_canon, canon_len);
        memcpy(out + canon_len, suffix, suffix_len + 1);
    }

    *is_glob = 1;
    *base_len = (int)canon_len;

    if (canon_len == 1)
        log_msg(LOG_WARNING,
                "config_load: glob pattern based at / can be expensive to walk: %s",
                raw);
    return 0;
}

/*
 * Count entries of a NULL-terminated string array.
 */
static int string_array_len(char **arr)
{
    int n = 0;
    if (arr)
        while (arr[n])
            n++;
    return n;
}

/*
 * Append one prepared rule to a section array.  The entry is already
 * canonicalized and bounds-checked by rule_pattern_set(), so this is a
 * plain copy past the shared per-section cap.
 */
static void rule_append(RuleEntry *rules, int *count, const RuleEntry *e)
{
    if (*count >= MAX_RULES)
    {
        log_msg(LOG_WARNING, "config_load: too many allow/deny rules (max %d)",
                MAX_RULES);
        return;
    }
    rules[*count] = *e;
    (*count)++;
}

/*
 * add_rule: parse one [allowlist]/[unsafe_allowlist]/[denylist] line and
 * append the resulting rule(s).  Format:
 *
 *   /path/to/bin = /path/to/target   scoped rule (equal-or-under match)
 *   /path/to/bin                     global rule (no '=' separator)
 *
 * Either side may be a glob ('*' / '**', the [protected_paths] engine).
 * Both sides are validated and canonicalized by rule_pattern_set(): the
 * wildcard-free base is canonicalized and the suffix kept verbatim.
 * Exact binaries match by strcmp and exact targets by path_under()
 * (equal or under) at event time; globs are matched full-path by
 * glob_match_path() in fanotify.c.  Malformed patterns skip that
 * expanded copy with a log (fail closed).
 *
 * Both sides expand '~' for every real user, mirroring [protected_paths].
 * When both sides expand, entry i pairs user i's binary with user i's
 * target (both expansions enumerate /etc/passwd identically); when only
 * one side expands, the fixed side is shared by every expanded entry.
 * Trailing slashes are stripped by canonicalize_path so matching is
 * "equal or under".
 *
 * A '=' with an empty right side is a parse error, and a purely numeric
 * right side is the pre-rework "binary = ttl" format — both log a warning
 * and skip the line.  Returns 0 on success (skips included), -1 on
 * out-of-memory.
 */
static int add_rule(RuleEntry *rules, int *count, const char *line)
{
    char left[PATH_MAX * 2];
    char bin_raw[PATH_MAX];
    const char *tgt_raw = NULL;

    snprintf(left, sizeof(left), "%s", line);

    char *eq = strchr(left, '=');
    if (eq)
    {
        *eq = '\0';
        tgt_raw = trim(eq + 1);
    }
    const char *b = trim(left);
    if (!b || b[0] == '\0')
    {
        log_msg(LOG_ERR, "config_load: malformed rule line: %s", line);
        return 0;
    }
    snprintf(bin_raw, sizeof(bin_raw), "%s", b);

    if (tgt_raw)
    {
        if (*tgt_raw == '\0')
        {
            log_msg(LOG_ERR,
                    "config_load: empty target after '='; use a bare binary "
                    "line for a global rule: %s", line);
            return 0;
        }

        /* Legacy-format guard: entries used to be "binary = ttl_seconds". */
        int numeric = 1;
        for (const char *p = tgt_raw; *p != '\0'; p++)
        {
            if (*p < '0' || *p > '9')
            {
                numeric = 0;
                break;
            }
        }
        if (numeric)
        {
            log_msg(LOG_ERR,
                    "config_load: numeric target \"%s\" looks like a legacy "
                    "TTL; rules are now \"binary = target\" — skipping",
                    tgt_raw);
            return 0;
        }
    }

    /* Expand both sides for all users; non-'~/' paths yield a single copy. */
    char **bins = expand_home_all_users(bin_raw);
    if (!bins)
        return -1;

    char **tgts = NULL;
    if (tgt_raw)
    {
        tgts = expand_home_all_users(tgt_raw);
        if (!tgts)
        {
            free_string_array(bins);
            return -1;
        }
    }

    int nb = string_array_len(bins);
    int nt = tgts ? string_array_len(tgts) : 1;
    int n = nb > nt ? nb : nt;

    for (int i = 0; i < n; i++)
    {
        const char *bpath = bins[i < nb ? i : nb - 1];
        const char *tpath = tgts ? tgts[i < nt ? i : nt - 1] : "";

        if (bpath[0] != '/' || (tpath[0] != '\0' && tpath[0] != '/'))
        {
            log_msg(LOG_ERR, "config_load: rule paths must be absolute: %s",
                    line);
            continue;
        }

        RuleEntry e;
        memset(&e, 0, sizeof(e));
        if (rule_pattern_set(e.binary, sizeof(e.binary), &e.binary_is_glob,
                             &e.binary_base_len, bpath) < 0)
            continue; /* malformed glob: rejected with a log */
        if (tpath[0] != '\0')
        {
            if (rule_pattern_set(e.target_path, sizeof(e.target_path),
                                 &e.target_is_glob, &e.target_base_len,
                                 tpath) < 0)
                continue;
        }

        rule_append(rules, count, &e);
    }

    free_string_array(bins);
    if (tgts)
        free_string_array(tgts);
    return 0;
}

/*
 * protected_path_set: canonicalize one [protected_paths] entry into pp
 * via the shared rule_pattern_set() validator (rules accept the same
 * pattern syntax, so both share one implementation).  Exact entries
 * keep the historical behavior; malformed globs are rejected.
 *
 * Returns 0 on success, -1 when the entry is rejected.
 */
static int protected_path_set(ProtectedPath *pp, const char *raw)
{
    memset(pp, 0, sizeof(*pp));
    return rule_pattern_set(pp->path, sizeof(pp->path), &pp->is_glob,
                            &pp->base_len, raw);
}

/* Sections of fileshield.conf; SECTION_NONE is "before/outside any". */
enum
{
    SECTION_NONE = 0,
    SECTION_PROTECTED,
    SECTION_ALLOWLIST,
    SECTION_SETTINGS,
    SECTION_DENYLIST,
    SECTION_UNSAFE_ALLOWLIST
};

int config_load(const char *path, Config *cfg)
{
    if (!path)
        return -1;

    FILE *fp = fopen(path, "r");
    if (!fp)
    {
        log_msg(LOG_ERR, "config_load: cannot open %s", path);
        return -1;
    }

    /* The daemon runs as root: warn loudly about a config that another
     * user could modify. */
    if (geteuid() == 0)
    {
        struct stat st;
        if (fstat(fileno(fp), &st) == 0 && S_ISREG(st.st_mode))
        {
            if (st.st_uid != 0)
                log_msg(LOG_WARNING, "config_load: %s is not owned by root", path);
            if (st.st_mode & 022)
                log_msg(LOG_WARNING, "config_load: %s is writable by group/other", path);
        }
    }

    char line[PATH_MAX * 2];
    int section = SECTION_NONE;

    memset(cfg, 0, sizeof(*cfg));

    while (fgets(line, sizeof(line), fp))
    {
        if (!strchr(line, '\n') && !feof(fp))
        {
            log_msg(LOG_ERR, "config_load: line too long, skipping");
            int c;
            while ((c = fgetc(fp)) != '\n' && c != EOF)
                ;
            continue;
        }
        char *s = trim(line);

        if (*s == '\0' || *s == '#')
            continue;

        if (s[0] == '[')
        {
            char *close = strchr(s, ']');
            if (!close)
            {
                log_msg(LOG_ERR, "config_load: malformed section header: %s", s);
                fclose(fp);
                return -1;
            }
            *close = '\0';
            if (strcmp(s + 1, "protected_paths") == 0)
                section = SECTION_PROTECTED;
            else if (strcmp(s + 1, "allowlist") == 0)
                section = SECTION_ALLOWLIST;
            else if (strcmp(s + 1, "unsafe_allowlist") == 0)
                section = SECTION_UNSAFE_ALLOWLIST;
            else if (strcmp(s + 1, "settings") == 0)
                section = SECTION_SETTINGS;
            else if (strcmp(s + 1, "denylist") == 0)
                section = SECTION_DENYLIST;
            else
                section = SECTION_NONE;
            continue;
        }

        if (section == SECTION_PROTECTED)
        {
            /*
             * A leading '!' marks an exclusion: it protects nothing
             * itself and removes matching paths from the protection of
             * every positive entry (deny wins; config order is
             * irrelevant).  '!' elsewhere is an ordinary path
             * character.  Exclusions must be absolute after '~'
             * expansion — unlike legacy exact positives, a relative one
             * can never match a canonical target.
             */
            const char *raw = s;
            int is_exclude = 0;
            if (raw[0] == '!')
            {
                is_exclude = 1;
                raw = trim(s + 1);
                if (*raw == '\0')
                {
                    log_msg(LOG_ERR, "config_load: empty exclusion: %s", s);
                    continue;
                }
            }

            /* Expand ~/... for every user in /etc/passwd so that each
             * user's home directory is protected, not just root's. */
            char **paths = expand_home_all_users(raw);
            if (!paths)
            {
                log_msg(LOG_ERR, "config_load: out of memory");
                fclose(fp);
                return -1;
            }
            for (int pi = 0; paths[pi] != NULL; pi++)
            {
                if (cfg->protected_count >= MAX_PATHS)
                {
                    log_msg(LOG_WARNING, "config_load: too many protected paths (max %d)", MAX_PATHS);
                    break;
                }
                if (is_exclude && paths[pi][0] != '/')
                {
                    log_msg(LOG_ERR, "config_load: exclusion must be absolute: %s", s);
                    continue;
                }
                ProtectedPath *pp = &cfg->protected[cfg->protected_count];
                if (protected_path_set(pp, paths[pi]) < 0)
                    continue; /* malformed glob: rejected with a warning */
                pp->is_exclude = is_exclude;
                if (is_exclude)
                {
                    cfg->exclude_idx[cfg->exclude_count] = cfg->protected_count;
                    cfg->exclude_count++;
                    /* Audit trail: every carve-out is visible in the journal. */
                    log_msg(LOG_INFO, "config_load: exclusion: !%s", pp->path);
                }
                cfg->protected_count++;
            }
            free_string_array(paths);
        }
        else if (section == SECTION_ALLOWLIST)
        {
            /* [allowlist] "binary = target" or a bare binary (global). */
            if (add_rule(cfg->allowlist, &cfg->allowlist_count, s) < 0)
            {
                log_msg(LOG_ERR, "config_load: out of memory");
                fclose(fp);
                return -1;
            }
        }
        else if (section == SECTION_UNSAFE_ALLOWLIST)
        {
            /* [unsafe_allowlist]: same format as [allowlist], but grants
             * skip the binary hash pinning entirely. */
            if (add_rule(cfg->unsafe_allowlist, &cfg->unsafe_allowlist_count, s) < 0)
            {
                log_msg(LOG_ERR, "config_load: out of memory");
                fclose(fp);
                return -1;
            }
        }
        else if (section == SECTION_SETTINGS)
        {
            /* [settings] key = value */
            char *eq = strchr(s, '=');
            if (!eq)
                continue;
            *eq = '\0';
            const char *key = trim(s);
            char *val = trim(eq + 1);
            if (strcmp(key, "user_ttl") == 0)
            {
                int ttl;
                if (sscanf(val, "%d", &ttl) == 1 && ttl > 0)
                {
                    if (ttl > FS_MAX_TTL_SECONDS)
                    {
                        log_msg(LOG_WARNING,
                                "config_load: user_ttl %d clamped to %d seconds",
                                ttl, FS_MAX_TTL_SECONDS);
                        ttl = FS_MAX_TTL_SECONDS;
                    }
                    cfg->user_ttl_seconds = ttl;
                }
                else
                    log_msg(LOG_ERR, "config_load: invalid user_ttl: %s", val);
            }
            else if (strcmp(key, "session_ttl") == 0)
            {
                /* 0 is a valid value: session decisions then live exactly
                 * as long as the session leader (the shell). */
                int ttl;
                if (sscanf(val, "%d", &ttl) == 1 && ttl >= 0)
                {
                    if (ttl > FS_MAX_TTL_SECONDS)
                    {
                        log_msg(LOG_WARNING,
                                "config_load: session_ttl %d clamped to %d seconds",
                                ttl, FS_MAX_TTL_SECONDS);
                        ttl = FS_MAX_TTL_SECONDS;
                    }
                    cfg->session_ttl_seconds = ttl;
                }
                else
                    log_msg(LOG_ERR, "config_load: invalid session_ttl: %s", val);
            }
            else if (strcmp(key, "debug") == 0)
            {
                /* Enables the per-event LOG_DEBUG firehose at runtime. */
                if (strcmp(val, "yes") == 0 || strcmp(val, "true") == 0 ||
                    strcmp(val, "1") == 0)
                    log_set_debug(1);
                else if (strcmp(val, "no") == 0 || strcmp(val, "false") == 0 ||
                         strcmp(val, "0") == 0)
                    log_set_debug(0);
                else
                    log_msg(LOG_ERR,
                            "config_load: invalid debug value (yes|no): %s",
                            val);
            }
        }
        else if (section == SECTION_DENYLIST)
        {
            /* [denylist] "binary = target" or a bare binary (global). */
            if (add_rule(cfg->denylist, &cfg->denylist_count, s) < 0)
            {
                log_msg(LOG_ERR, "config_load: out of memory");
                fclose(fp);
                return -1;
            }
        }
    }

    fclose(fp);
    /*
     * Deliberately do NOT publish cfg through g_config here.  The caller
     * decides whether the parsed config is accepted; publishing during
     * the parse is what once left g_config dangling after a rejected
     * reload free()d the new config.  main.c sets g_config only after the
     * config is accepted and its marks are installed.
     */
    return 0;
}

void config_reset(Config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
}
