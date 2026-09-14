#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>

#include "cache.h"

#define CACHE_MAX_ENTRIES 4096

/* How many ancestors are walked when granting/matching a session scope. */
#define SESSION_WALK_MAX 16

/*
 * Upper bound for any cached decision (1 year): keeps `now + ttl` safe
 * even with 32-bit time_t and bounds how long a grant can outlive a
 * policy change.  config.c clamps at parse time with a warning; this is
 * the defensive backstop (cache.c stays standalone for unit tests).
 */
#define CACHE_MAX_TTL_SECONDS (365 * 24 * 60 * 60)

typedef enum
{
    CACHE_SCOPE_PID = 0,    /* exact process: pid + start time            */
    CACHE_SCOPE_SESSION = 1 /* grant root process and its descendants     */
} cache_scope_t;

typedef struct
{
    cache_scope_t scope;
    pid_t pid; /* PID: requester.  SESSION: grant root process. */
    unsigned long long starttime; /* /proc/<pid>/stat field 22; 0 = unknown */
    char binary_path[PATH_MAX];

    /* SESSION: binary identity captured at grant time so replacing the
     * binary invalidates the grant.  Unused for PID scope. */
    dev_t bin_dev;
    ino_t bin_ino;
    off_t bin_size;
    time_t bin_mtime;
    long bin_mtime_nsec;

    time_t expiry_time; /* 0 = no time cap (session lifetime only) */
} cache_entry_t;

static cache_entry_t cache[CACHE_MAX_ENTRIES];
static int cache_initialized = 0;

static void cache_init(void)
{
    memset(cache, 0, sizeof(cache));
    cache_initialized = 1;
}

/*
 * Read ppid (field 4) and start time (field 22) of /proc/<pid>/stat.
 * Returns 0 on success.  The comm field may contain spaces and
 * parentheses, so parsing starts after the last ')'.
 */
static int read_proc_stat(pid_t pid, pid_t *ppid_out,
                          unsigned long long *starttime_out)
{
    char path[64];
    char buf[1024];
    FILE *f;
    size_t n;

    snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
    f = fopen(path, "r");
    if (!f)
        return -1;
    n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (n == 0)
        return -1;
    buf[n] = '\0';

    char *q = strrchr(buf, ')');
    if (!q)
        return -1;
    q++;
    while (*q == ' ')
        q++;
    if (*q == '\0')
        return -1;
    q++; /* skip the single-character state field (field 3) */

    pid_t ppid = 0;
    unsigned long long value = 0;
    for (int field = 4; field <= 22; field++)
    {
        char *endp;
        while (*q == ' ')
            q++;
        value = strtoull(q, &endp, 10);
        if (endp == q)
            return -1;
        if (field == 4)
            ppid = (pid_t)value;
        q = endp;
    }

    if (ppid_out)
        *ppid_out = ppid;
    if (starttime_out)
        *starttime_out = value;
    return 0;
}

static unsigned long long proc_start_time(pid_t pid)
{
    unsigned long long st = 0;
    if (read_proc_stat(pid, NULL, &st) < 0)
        return 0;
    return st;
}

static pid_t proc_ppid(pid_t pid)
{
    pid_t pp = 0;
    if (read_proc_stat(pid, &pp, NULL) < 0)
        return 0;
    return pp;
}

/*
 * Pick the scope root for an "Allow Session" grant: the process's POSIX
 * session leader when it is one of its ancestors (the terminal shell),
 * otherwise the immediate parent, otherwise the process itself.  Matching
 * walks the requester's ancestry for this process and verifies its start
 * time, so the grant cannot be inherited through PID reuse and lives
 * exactly as long as the grant root does.
 */
static int find_session_root(pid_t pid, pid_t *root,
                             unsigned long long *root_start)
{
    pid_t sid = getsid(pid);
    pid_t cur = pid;
    unsigned long long st = 0;
    pid_t pp = 0;

    for (int depth = 0; depth < SESSION_WALK_MAX; depth++)
    {
        if (cur > 1 && cur == sid &&
            read_proc_stat(cur, NULL, &st) == 0)
        {
            *root = cur;
            *root_start = st;
            return 0;
        }
        if (read_proc_stat(cur, &pp, NULL) < 0 || pp <= 1)
            break;
        cur = pp;
    }

    /* No session leader found in the ancestry: use the parent. */
    pp = proc_ppid(pid);
    st = 0;
    if (pp > 1 && read_proc_stat(pp, NULL, &st) == 0)
    {
        *root = pp;
        *root_start = st;
        return 0;
    }

    /* Last resort: scope the grant to the process itself. */
    st = 0;
    if (read_proc_stat(pid, NULL, &st) == 0)
    {
        *root = pid;
        *root_start = st;
        return 0;
    }
    return -1;
}

/* 1 when e's grant root appears in pid's ancestry with the same start time. */
static int session_matches(const cache_entry_t *e, pid_t pid)
{
    pid_t cur = pid;

    if (e->starttime == 0)
        return 0;

    for (int depth = 0; depth < SESSION_WALK_MAX && cur > 1; depth++)
    {
        if (cur == e->pid)
        {
            unsigned long long st = proc_start_time(cur);
            return st != 0 && st == e->starttime;
        }
        pid_t pp = proc_ppid(cur);
        if (pp <= 1 || pp == cur)
            break;
        cur = pp;
    }
    return 0;
}

/* 1 when the binary still has the identity captured at grant time. */
static int binary_identity_matches(const cache_entry_t *e, const char *binary)
{
    struct stat st;

    if (stat(binary, &st) != 0)
        return 0;
    return st.st_dev == e->bin_dev && st.st_ino == e->bin_ino &&
           st.st_size == e->bin_size &&
           st.st_mtim.tv_sec == e->bin_mtime &&
           st.st_mtim.tv_nsec == e->bin_mtime_nsec;
}

int cache_lookup(pid_t pid, const char *binary)
{
    time_t now;
    int i;

    if (!binary)
        return 0;

    if (!cache_initialized)
        cache_init();

    now = time(NULL);

    for (i = 0; i < CACHE_MAX_ENTRIES; i++)
    {
        cache_entry_t *e = &cache[i];

        if (e->pid == 0)
            continue;
        if (strcmp(e->binary_path, binary) != 0)
            continue;

        if (e->scope == CACHE_SCOPE_PID)
        {
            if (e->pid != pid)
                continue;
            /* Reject a different process that reused the same PID. */
            if (e->starttime != proc_start_time(pid))
            {
                e->pid = 0;
                return 0;
            }
        }
        else /* CACHE_SCOPE_SESSION */
        {
            if (!session_matches(e, pid))
                continue;
            if (!binary_identity_matches(e, binary))
            {
                e->pid = 0; /* binary replaced: grant is void */
                return 0;
            }
        }

        if (e->expiry_time != 0 && e->expiry_time < now)
        {
            e->pid = 0;
            return 0;
        }

        if (e->expiry_time == 0)
            return 1; /* session grant: valid until the root exits */
        return (int)(e->expiry_time - now);
    }

    return 0;
}

static int find_slot(cache_scope_t scope, pid_t pid, const char *binary)
{
    int free_slot = -1;

    for (int i = 0; i < CACHE_MAX_ENTRIES; i++)
    {
        if (cache[i].pid != 0)
        {
            if (cache[i].scope == scope && cache[i].pid == pid &&
                strcmp(cache[i].binary_path, binary) == 0)
                return i;
            continue;
        }
        if (free_slot < 0)
            free_slot = i;
    }
    return free_slot;
}

void cache_insert(pid_t pid, const char *binary, int ttl_seconds)
{
    time_t now;
    int slot;

    if (!cache_initialized)
        cache_init();

    if (binary == NULL)
        return;

    if (ttl_seconds <= 0)
        return;
    if (ttl_seconds > CACHE_MAX_TTL_SECONDS)
        ttl_seconds = CACHE_MAX_TTL_SECONDS;

    now = time(NULL);
    slot = find_slot(CACHE_SCOPE_PID, pid, binary);
    if (slot < 0)
        return;

    memset(&cache[slot], 0, sizeof(cache[slot]));
    cache[slot].scope = CACHE_SCOPE_PID;
    cache[slot].pid = pid;
    cache[slot].starttime = proc_start_time(pid);
    strncpy(cache[slot].binary_path, binary, PATH_MAX - 1);
    cache[slot].binary_path[PATH_MAX - 1] = '\0';
    cache[slot].expiry_time = now + ttl_seconds;
}

/*
 * Grant access to the caller's session subtree.  ttl_seconds == 0 means
 * the grant lasts until the session root exits; a positive value also
 * caps it in time.  Returns 0 on success, -1 when the grant could not be
 * recorded (no verifiable ancestry or binary identity): callers should
 * treat that as "grant not remembered" — the next access re-prompts.
 */
int cache_insert_session(pid_t pid, const char *binary, int ttl_seconds)
{
    time_t now;
    int slot;
    pid_t root = 0;
    unsigned long long root_start = 0;
    struct stat st;

    if (!binary || ttl_seconds < 0)
        return -1;

    if (!cache_initialized)
        cache_init();

    if (ttl_seconds > CACHE_MAX_TTL_SECONDS)
        ttl_seconds = CACHE_MAX_TTL_SECONDS;

    if (find_session_root(pid, &root, &root_start) < 0)
        return -1;
    if (stat(binary, &st) != 0)
        return -1;

    now = time(NULL);
    slot = find_slot(CACHE_SCOPE_SESSION, root, binary);
    if (slot < 0)
        return -1;

    memset(&cache[slot], 0, sizeof(cache[slot]));
    cache[slot].scope = CACHE_SCOPE_SESSION;
    cache[slot].pid = root;
    cache[slot].starttime = root_start;
    strncpy(cache[slot].binary_path, binary, PATH_MAX - 1);
    cache[slot].binary_path[PATH_MAX - 1] = '\0';
    cache[slot].bin_dev = st.st_dev;
    cache[slot].bin_ino = st.st_ino;
    cache[slot].bin_size = st.st_size;
    cache[slot].bin_mtime = st.st_mtim.tv_sec;
    cache[slot].bin_mtime_nsec = st.st_mtim.tv_nsec;
    cache[slot].expiry_time = ttl_seconds > 0 ? now + ttl_seconds : 0;
    return 0;
}

void cache_expire(void)
{
    time_t now;
    int i;

    if (!cache_initialized)
        cache_init();

    now = time(NULL);

    for (i = 0; i < CACHE_MAX_ENTRIES; i++)
    {
        /* expiry_time == 0 is a session grant with no time cap. */
        if (cache[i].pid == 0 || cache[i].expiry_time == 0)
            continue;
        if (cache[i].expiry_time < now)
            cache[i].pid = 0;
    }
}

int cache_entry_count(void)
{
    time_t now;
    int count = 0;
    int i;

    if (!cache_initialized)
        cache_init();

    now = time(NULL);

    for (i = 0; i < CACHE_MAX_ENTRIES; i++)
    {
        if (cache[i].pid == 0)
            continue;
        if (cache[i].expiry_time == 0 || cache[i].expiry_time >= now)
            count++;
    }

    return count;
}
