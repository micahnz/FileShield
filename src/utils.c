#include "utils.h"

#include <errno.h>
#include <fcntl.h>
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

static int g_log_debug = 0;

void log_set_debug(int enabled)
{
    g_log_debug = enabled ? 1 : 0;
}

char *proc_exe_path(pid_t pid)
{
    char linkpath[64];
    int n;

    n = snprintf(linkpath, sizeof(linkpath), "/proc/%d/exe", pid);
    if ((size_t)n >= sizeof(linkpath))
        return NULL;

    char buf[PATH_MAX];
    ssize_t len = readlink(linkpath, buf, sizeof(buf) - 1);
    /* A truncated result (a path near PATH_MAX with the " (deleted)"
     * suffix) is unverifiable: report failure rather than a wrong path. */
    if (len < 0 || len >= (ssize_t)sizeof(buf) - 1)
        return NULL;
    buf[len] = '\0';
    return strdup(buf);
}

pid_t get_ppid(pid_t pid)
{
    char path[64], line[256];
    FILE *f;
    pid_t ppid = 0;

    snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
    f = fopen(path, "r");
    if (!f)
        return 0;
    while (fgets(line, sizeof(line), f))
    {
        if (sscanf(line, "PPid:\t%d", &ppid) == 1)
            break;
    }
    fclose(f);
    return ppid;
}

int read_comm(pid_t pid, char *out, size_t size)
{
    char path[64];
    FILE *f;
    size_t len;

    if (size < 2)
        return -1;

    snprintf(path, sizeof(path), "/proc/%d/comm", (int)pid);
    f = fopen(path, "r");
    if (!f)
        return -1;
    if (!fgets(out, (int)size, f))
    {
        fclose(f);
        return -1;
    }
    fclose(f);
    len = strlen(out);
    if (len > 0 && out[len - 1] == '\n')
        out[len - 1] = '\0';
    return 0;
}

int read_cmdline(pid_t pid, char *out, size_t size)
{
    char path[64];

    if (size < 2)
        return -1;
    snprintf(path, sizeof(path), "/proc/%d/cmdline", (int)pid);
    int fd_c = open(path, O_RDONLY | O_CLOEXEC);
    if (fd_c < 0)
        return -1;

    ssize_t n = read(fd_c, out, size - 1);
    close(fd_c);
    if (n <= 0)
        return -1;

    /* Replace every embedded NUL with a space, except the last one. */
    for (ssize_t i = 0; i < n - 1; i++)
        if (out[i] == '\0')
            out[i] = ' ';
    out[n] = '\0';
    /* Trim any trailing space left by the last NUL. */
    while (n > 0 && out[n - 1] == ' ')
        out[--n] = '\0';
    return (int)n;
}

void log_msg(int priority, const char *fmt, ...)
{
    va_list a1, a2;

    /* Debug firehose gate: per-event plumbing stays out of the journal
     * unless the operator explicitly asked for it. */
    if (priority == LOG_DEBUG && !g_log_debug)
        return;

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

int path_under_len(const char *path, const char *dir, size_t dlen)
{
    size_t plen = strlen(path);

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

int path_under(const char *path, const char *dir)
{
    return path_under_len(path, dir, strlen(dir));
}

/* ------------------------------------------------------------------ */
/*  glob matching for protected paths                                  */
/* ------------------------------------------------------------------ */

/* Length of the path segment starting at s (up to '/' or NUL). */
static size_t seg_len(const char *s)
{
    const char *slash = strchr(s, '/');
    return slash ? (size_t)(slash - s) : strlen(s);
}

/*
 * seg_glob_match: byte-wise '*' wildcard match confined to one path
 * segment.  Only '*' is special; the classic single-backtrack loop
 * keeps it allocation-free with bounded work per segment.
 */
static int seg_glob_match(const char *pat, size_t plen,
                          const char *name, size_t nlen)
{
    size_t pi = 0, ni = 0;
    size_t star_pi = 0, star_ni = 0;
    int have_star = 0;

    while (ni < nlen)
    {
        if (pi < plen && pat[pi] == '*')
        {
            have_star = 1;
            star_pi = pi++;
            star_ni = ni;
        }
        else if (pi < plen && pat[pi] == name[ni])
        {
            pi++;
            ni++;
        }
        else if (have_star)
        {
            pi = star_pi + 1;
            ni = ++star_ni;
        }
        else
        {
            return 0;
        }
    }

    while (pi < plen && pat[pi] == '*')
        pi++;
    return pi == plen;
}

int glob_base_len(const char *pattern)
{
    const char *seg = pattern;

    if (*seg == '/')
        seg++;

    for (;;)
    {
        const char *end = seg;
        while (*end != '\0' && *end != '/')
            end++;

        if (memchr(seg, '*', (size_t)(end - seg)) != NULL)
        {
            if (seg == pattern)
                return 0; /* wildcard in the first segment: no base */
            if (seg == pattern + 1 && pattern[0] == '/')
                return 1; /* wildcard directly under root: base is "/" */
            return (int)(seg - pattern - 1);
        }
        if (*end == '\0')
            return (int)(end - pattern);
        seg = end + 1;
    }
}

int glob_match_path(const char *pattern, const char *path)
{
    const char *pp = pattern; /* current pattern segment */
    const char *sp = path;    /* current path segment */
    size_t plen = seg_len(pp);
    size_t slen = seg_len(sp);

    const char *star_pp = NULL; /* pattern just after the active "**" */
    const char *star_sp = NULL; /* path position the "**" started at */
    size_t star_slen = 0;

    while (*sp != '\0')
    {
        int pat_seg = (*pp != '\0' || plen > 0);

        if (pat_seg && plen == 2 && pp[0] == '*' && pp[1] == '*')
        {
            /* Globstar: remember it, then try it with zero segments. */
            star_pp = pp + 2;
            if (*star_pp == '/')
                star_pp++;
            star_sp = sp;
            star_slen = slen;
            pp = star_pp;
            plen = seg_len(pp);
            continue;
        }
        if (pat_seg && seg_glob_match(pp, plen, sp, slen))
        {
            pp += plen;
            if (*pp == '/')
                pp++;
            plen = seg_len(pp);
            sp += slen;
            if (*sp == '/')
                sp++;
            slen = seg_len(sp);
            continue;
        }
        if (star_pp != NULL)
        {
            /* Let the remembered "**" eat one more path segment. */
            star_sp += star_slen;
            if (*star_sp == '/')
                star_sp++;
            star_slen = seg_len(star_sp);
            pp = star_pp;
            plen = seg_len(pp);
            sp = star_sp;
            slen = star_slen;
            continue;
        }
        return 0;
    }

    /* Path exhausted: only trailing "**" segments may remain. */
    while (*pp != '\0' || plen > 0)
    {
        if (plen == 2 && pp[0] == '*' && pp[1] == '*')
        {
            pp += 2;
            if (*pp == '/')
                pp++;
            plen = seg_len(pp);
            continue;
        }
        return 0;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/*  /proc/<pid>/stat field extraction                                  */
/* ------------------------------------------------------------------ */

int proc_stat_session(pid_t pid, unsigned long long *sid_out,
                      unsigned long long *start_out)
{
    char path[64];
    char buf[1024];

    snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
    /*
     * open()/read() instead of fopen()/fread(): this sits on the hot
     * path (PID-reuse check on every cache hit).  FILE stream setup and
     * teardown is measurable here — 7.16 us with stdio vs 5.70 us with
     * raw descriptors in tests/bench_hotpath.c.
     */
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return -1;
    buf[n] = '\0';

    /*
     * The comm field (field 2) may contain spaces and parentheses, so the
     * fixed numeric fields cannot be addressed by splitting on whitespace
     * from the left.  Everything after the LAST ')' is stable: the next
     * token is the single state character (field 3), then fields 4..52.
     */
    char *q = strrchr(buf, ')');
    if (!q || q[1] == '\0')
        return -1;
    q++;
    while (*q == ' ')
        q++;
    if (*q == '\0')
        return -1;
    q++; /* skip the single-character state field (field 3) */

    /* Fields 4..22 in order; collect 6 and 22, stop after 22. */
    unsigned long long session = 0;
    unsigned long long start = 0;
    for (int i = 4; i <= 22; i++)
    {
        while (*q == ' ')
            q++;
        char *endp;
        unsigned long long v = strtoull(q, &endp, 10);
        if (endp == q)
            return -1;
        if (i == 6)
            session = v;
        if (i == 22)
            start = v;
        q = endp;
    }

    if (sid_out)
        *sid_out = session;
    if (start_out)
        *start_out = start;
    return 0;
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

    const struct passwd *pw;
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
            {
                /* Fail the whole expansion: skipping one user on OOM
                 * would silently leave their home unprotected while the
                 * config still "loads fine".  Callers treat NULL as
                 * fatal, which is the fail-closed direction. */
                result[count] = NULL;
                endpwent();
                free_string_array(result);
                return NULL;
            }
            result = tmp;
            capacity = new_cap;
        }

        size_t len = strlen(pw->pw_dir) + strlen(rest) + 1;
        char *expanded = malloc(len);
        if (!expanded)
        {
            result[count] = NULL;
            endpwent();
            free_string_array(result);
            return NULL;
        }
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
