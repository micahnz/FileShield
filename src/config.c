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

int config_load(const char *path, Config *cfg)
{
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
            if (cfg->allowlist_count >= MAX_ALLOWLIST)
            {
                log_msg(LOG_WARNING, "config_load: too many allowlist entries (max %d)", MAX_ALLOWLIST);
                continue;
            }
            char *eq = strchr(s, '=');
            if (!eq)
            {
                log_msg(LOG_ERR, "config_load: malformed allowlist line: %s", s);
                continue;
            }
            *eq = '\0';
            char *binary = trim(s);
            char *ttl_str = trim(eq + 1);

            int ttl;
            if (sscanf(ttl_str, "%d", &ttl) != 1 || ttl <= 0)
            {
                log_msg(LOG_ERR, "config_load: invalid TTL in allowlist: %s", ttl_str);
                continue;
            }

            char *expanded = expand_home(binary);
            if (!expanded)
            {
                log_msg(LOG_ERR, "config_load: out of memory");
                fclose(fp);
                return -1;
            }
            canonicalize_path(expanded,
                              cfg->allowlist[cfg->allowlist_count].binary,
                              sizeof(cfg->allowlist[cfg->allowlist_count].binary));
            cfg->allowlist[cfg->allowlist_count].ttl_seconds = ttl;
            cfg->allowlist_count++;
            free(expanded);
        }
        else if (section == 3)
        {
            /* [settings] key = value */
            char *eq = strchr(s, '=');
            if (!eq)
                continue;
            *eq = '\0';
            char *key = trim(s);
            char *val = trim(eq + 1);
            if (strcmp(key, "user_ttl") == 0)
            {
                int ttl;
                if (sscanf(val, "%d", &ttl) == 1 && ttl > 0)
                    cfg->user_ttl_seconds = ttl;
                else
                    log_msg(LOG_ERR, "config_load: invalid user_ttl: %s", val);
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
