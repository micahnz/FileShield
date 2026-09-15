#include "config.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

Config *g_config = NULL;

/*
 * Sanity bound for TTLs (1 year): keeps cache expiry arithmetic safe on
 * 32-bit time_t and prevents a typo from silently granting access for
 * decades.  cache_insert() clamps again defensively.
 */
#define MAX_TTL_SECONDS (365 * 24 * 60 * 60)

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

/* Append one parsed rule to a section array (shared per-section cap). */
static void rule_append(RuleEntry *rules, int *count,
                        const char *binary, const char *target)
{
    if (*count >= MAX_RULES)
    {
        log_msg(LOG_WARNING, "config_load: too many allow/deny rules (max %d)",
                MAX_RULES);
        return;
    }
    RuleEntry *e = &rules[*count];
    snprintf(e->binary, sizeof(e->binary), "%s", binary);
    snprintf(e->target_path, sizeof(e->target_path), "%s", target);
    (*count)++;
}

/*
 * add_rule: parse one [allowlist]/[denylist] line and append the resulting
 * rule(s).  Format:
 *
 *   /path/to/bin = /path/to/target   scoped rule (equal-or-under match)
 *   /path/to/bin                     global rule (no '=' separator)
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

        char bin_canon[PATH_MAX];
        char tgt_canon[PATH_MAX];
        canonicalize_path(bpath, bin_canon, sizeof(bin_canon));
        if (tpath[0] != '\0')
            canonicalize_path(tpath, tgt_canon, sizeof(tgt_canon));
        else
            tgt_canon[0] = '\0';

        rule_append(rules, count, bin_canon, tgt_canon);
    }

    free_string_array(bins);
    if (tgts)
        free_string_array(tgts);
    return 0;
}

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
    int section = 0;

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
                section = 1;
            else if (strcmp(s + 1, "allowlist") == 0)
                section = 2;
            else if (strcmp(s + 1, "settings") == 0)
                section = 3;
            else if (strcmp(s + 1, "denylist") == 0)
                section = 4;
            else
                section = 0;
            continue;
        }

        if (section == 1)
        {
            /* Expand ~/... for every user in /etc/passwd so that each
             * user's home directory is protected, not just root's. */
            char **paths = expand_home_all_users(s);
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
                canonicalize_path(paths[pi],
                                  cfg->protected[cfg->protected_count].path,
                                  sizeof(cfg->protected[cfg->protected_count].path));
                cfg->protected_count++;
            }
            free_string_array(paths);
        }
        else if (section == 2)
        {
            /* [allowlist] "binary = target" or a bare binary (global). */
            if (add_rule(cfg->allowlist, &cfg->allowlist_count, s) < 0)
            {
                log_msg(LOG_ERR, "config_load: out of memory");
                fclose(fp);
                return -1;
            }
        }
        else if (section == 3)
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
                    if (ttl > MAX_TTL_SECONDS)
                    {
                        log_msg(LOG_WARNING,
                                "config_load: user_ttl %d clamped to %d seconds",
                                ttl, MAX_TTL_SECONDS);
                        ttl = MAX_TTL_SECONDS;
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
                    if (ttl > MAX_TTL_SECONDS)
                    {
                        log_msg(LOG_WARNING,
                                "config_load: session_ttl %d clamped to %d seconds",
                                ttl, MAX_TTL_SECONDS);
                        ttl = MAX_TTL_SECONDS;
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
        else if (section == 4)
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
    g_config = cfg;
    return 0;
}

void config_reset(Config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
}
