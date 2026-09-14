#include "utils.h"

#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <syslog.h>
#include <unistd.h>

int g_foreground = 0;

char *proc_exe_path(pid_t pid)
{
    char linkpath[64];
    int n;

    n = snprintf(linkpath, sizeof(linkpath), "/proc/%d/exe", pid);
    if ((size_t)n >= sizeof(linkpath))
        return NULL;

    char buf[PATH_MAX];
    ssize_t len = readlink(linkpath, buf, sizeof(buf) - 1);
    if (len < 0)
        return NULL;
    buf[len] = '\0';
    return strdup(buf);
}

char *expand_home(const char *path)
{
    if (path[0] == '~' && (path[1] == '/' || path[1] == '\0'))
    {
        const char *home = getenv("HOME");
        if (!home)
            return strdup(path);

        if (path[1] == '\0')
            return strdup(home);

        const char *rest = path + 1;
        size_t len = strlen(home) + strlen(rest) + 1;
        char *out = malloc(len);
        if (!out)
            return NULL;
        snprintf(out, len, "%s%s", home, rest);
        return out;
    }
    return strdup(path);
}

void log_msg(int priority, const char *fmt, ...)
{
    va_list a1, a2;

    va_start(a1, fmt);
    va_copy(a2, a1);
    vsyslog(priority, fmt, a1);
    va_end(a1);

    /* Mirror to stderr only when it is attached to a terminal.  The unit
     * runs with --foreground, and systemd/journald captures stderr too, so
     * an unconditional mirror would duplicate every syslog message. */
    if (g_foreground && isatty(STDERR_FILENO))
    {
        vfprintf(stderr, fmt, a2);
        fputc('\n', stderr);
    }
    va_end(a2);
}

int path_under(const char *path, const char *dir)
{
    size_t plen = strlen(path);
    size_t dlen = strlen(dir);

    if (plen == 0)
        return 0;

    while (dlen > 1 && dir[dlen - 1] == '/')
        dlen--;

    if (dlen == 1 && dir[0] == '/')
        return 1;

    if (plen < dlen)
        return 0;
    if (memcmp(path, dir, dlen) != 0)
        return 0;

    return (plen == dlen || path[dlen] == '/');
}

/* ------------------------------------------------------------------ */
/*  multi-user home expansion                                          */
/* ------------------------------------------------------------------ */

char **expand_home_all_users(const char *path)
{
    /* Not a ~/... pattern: return a single-element array unchanged. */
    if (path[0] != '~' || (path[1] != '/' && path[1] != '\0'))
    {
        char **result = malloc(2 * sizeof(char *));
        if (!result)
            return NULL;
        result[0] = strdup(path);
        if (!result[0])
        {
            free(result);
            return NULL;
        }
        result[1] = NULL;
        return result;
    }

    /* rest is "" for bare "~" or "/subpath" for "~/subpath". */
    const char *rest = (path[1] == '/') ? (path + 1) : "";

    char **result = NULL;
    int count = 0;
    int capacity = 0;

    struct passwd *pw;
    setpwent();
    while ((pw = getpwent()) != NULL)
    {
        /* Skip system/service accounts; only expand for real users. */
        if (pw->pw_uid < 1000 || pw->pw_uid >= 65534)
            continue;
        if (!pw->pw_dir || pw->pw_dir[0] == '\0')
            continue;

        /* Grow the result array if needed (+1 for NULL terminator). */
        if (count + 1 >= capacity)
        {
            int new_cap = (capacity == 0) ? 16 : capacity * 2;
            char **tmp = realloc(result, (size_t)(new_cap + 1) * sizeof(char *));
            if (!tmp)
                continue; /* skip this user on OOM */
            result = tmp;
            capacity = new_cap;
        }

        size_t len = strlen(pw->pw_dir) + strlen(rest) + 1;
        char *expanded = malloc(len);
        if (!expanded)
            continue;
        snprintf(expanded, len, "%s%s", pw->pw_dir, rest);
        result[count++] = expanded;
    }
    endpwent();

    if (count == 0)
    {
        /* No users found — return the original path unchanged. */
        free(result);
        result = malloc(2 * sizeof(char *));
        if (!result)
            return NULL;
        result[0] = strdup(path);
        if (!result[0])
        {
            free(result);
            return NULL;
        }
        result[1] = NULL;
        return result;
    }

    result[count] = NULL;
    return result;
}

void free_string_array(char **arr)
{
    if (!arr)
        return;
    for (int i = 0; arr[i] != NULL; i++)
        free(arr[i]);
    free(arr);
}

/*
 * Close all fds >= first.  close_range(2) is the fast path; the fallback
 * loop is capped so a huge RLIMIT_NOFILE cannot turn this into a long scan.
 */
void close_fds_from(int first)
{
#ifdef SYS_close_range
    if (syscall(SYS_close_range, (unsigned int)first, ~0U, 0U) == 0)
        return;
#endif

    long max = sysconf(_SC_OPEN_MAX);
    if (max < 0)
        max = 1024;
    if (max > 65536)
        max = 65536;

    for (int fd = first; fd < (int)max; fd++)
        close(fd);
}
