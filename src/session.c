#include "session.h"
#include "utils.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

/*
 * Session-scoped decisions are deliberately runtime-only: they describe
 * what the user approved/denied in a terminal that exists right now, so
 * they are rebuilt from scratch after a daemon restart (fail closed).
 */
#define SESSION_MAX 256

typedef struct
{
    int used;
    pid_t sid;
    unsigned long long leader_start;
    char binary[PATH_MAX];
    char binary_sha512[129];
    char target[PATH_MAX];
    time_t expiry; /* mono_seconds() deadline; 0 = leader lifetime */
} SessionEntry;

static SessionEntry g_allow[SESSION_MAX];
static SessionEntry g_deny[SESSION_MAX];
static int g_allow_count = 0;
static int g_deny_count = 0;

/*
 * Resolve the POSIX session id and the session leader's start time for
 * pid.  Thin wrapper over the shared /proc/<pid>/stat parser; returns 0
 * on success, -1 when the process is gone.
 */
static int read_proc_session(pid_t pid, pid_t *sid_out,
                             unsigned long long *start_out)
{
    unsigned long long sid = 0;
    unsigned long long start = 0;

    if (proc_stat_session(pid, &sid, start_out ? &start : NULL) != 0)
        return -1;
    if (sid_out)
        *sid_out = (pid_t)sid;
    if (start_out)
        *start_out = start;
    return 0;
}

int session_id_of(pid_t pid, pid_t *sid_out, unsigned long long *leader_start_out)
{
    pid_t sid;
    unsigned long long leader_start;

    if (read_proc_session(pid, &sid, NULL) != 0)
        return -1;

    /* The leader's start time, not the requester's: a recycled SID must
     * not resurrect a previous session's decisions. */
    if (read_proc_session(sid, NULL, &leader_start) != 0)
        return -1;

    if (sid_out)
        *sid_out = sid;
    if (leader_start_out)
        *leader_start_out = leader_start;
    return 0;
}

static int leader_alive(pid_t sid, unsigned long long start)
{
    unsigned long long current;

    if (read_proc_session(sid, NULL, &current) != 0)
        return 0;
    return current == start;
}

static int entry_expired(const SessionEntry *e, time_t now)
{
    return e->expiry != 0 && e->expiry < now;
}

static int hash_matches(const SessionEntry *e, const char *bin_sha512)
{
    if (e->binary_sha512[0] == '\0')
        return 1;
    if (!bin_sha512 || bin_sha512[0] == '\0')
        return 0; /* cannot verify the approved binary: fail closed */
    return strcmp(e->binary_sha512, bin_sha512) == 0;
}

/* Common path-level checks shared by all matchers.  Never matches an
 * entry without a target, and lazily drops dead/expired entries. */
static int entry_covers(SessionEntry *e, time_t now, pid_t sid,
                        const char *binary, const char *target)
{
    if (!e->used)
        return 0;
    if (entry_expired(e, now) || !leader_alive(e->sid, e->leader_start))
    {
        e->used = 0;
        return 0;
    }
    if (!binary || !target || target[0] == '\0')
        return 0;
    return e->sid == sid && strcmp(e->binary, binary) == 0 &&
           strcmp(e->target, target) == 0;
}

static int list_match(SessionEntry *list, int count, pid_t sid,
                      const char *binary, const char *bin_sha512,
                      const char *target)
{
    time_t now = mono_seconds();

    for (int i = 0; i < count; i++)
    {
        SessionEntry *e = &list[i];
        if (!entry_covers(e, now, sid, binary, target))
            continue;
        if (hash_matches(e, bin_sha512))
            return 1;
    }
    return 0;
}

int session_allow_match(pid_t sid, const char *binary, const char *bin_sha512,
                        const char *target)
{
    return list_match(g_allow, g_allow_count, sid, binary, bin_sha512, target);
}

int session_deny_match(pid_t sid, const char *binary, const char *bin_sha512,
                       const char *target)
{
    return list_match(g_deny, g_deny_count, sid, binary, bin_sha512, target);
}

static void list_add(SessionEntry *list, int *count, pid_t sid,
                     unsigned long long leader_start, const char *binary,
                     const char *bin_sha512, const char *target, int ttl_seconds)
{
    if (!binary || !target || target[0] == '\0')
        return;

    if (ttl_seconds < 0)
        ttl_seconds = 0;
    if (ttl_seconds > FS_MAX_TTL_SECONDS)
        ttl_seconds = FS_MAX_TTL_SECONDS;

    /* Refresh an identical entry instead of appending a duplicate. */
    SessionEntry *e = NULL;
    for (int i = 0; i < *count; i++)
    {
        SessionEntry *c = &list[i];
        if (c->used && c->sid == sid && c->leader_start == leader_start &&
            strcmp(c->binary, binary) == 0 && strcmp(c->target, target) == 0)
        {
            e = c;
            break;
        }
    }

    if (!e)
    {
        int slot;
        if (*count < SESSION_MAX)
        {
            /* Reclaim a hole first: lazily-dropped dead entries (expired
             * or dead-leader) would otherwise leave the table full of
             * unused slots that every insert shifts or evicts past. */
            slot = -1;
            for (int i = 0; i < *count; i++)
            {
                if (!list[i].used)
                {
                    slot = i;
                    break;
                }
            }
            if (slot < 0)
                slot = (*count)++;
        }
        else
        {
            /* Full: reclaim a dead hole before dropping a live entry;
             * only when every slot is live is the oldest (slot 0)
             * evicted, which the log records. */
            slot = -1;
            for (int i = 0; i < SESSION_MAX; i++)
            {
                if (!list[i].used)
                {
                    slot = i;
                    break;
                }
            }
            if (slot < 0)
            {
                log_msg(LOG_INFO,
                        "session table full; dropping the oldest entry "
                        "(sid %d, %s -> %s)",
                        (int)list[0].sid, list[0].binary, list[0].target);
                memmove(&list[0], &list[1],
                        sizeof(SessionEntry) * (SESSION_MAX - 1));
                slot = SESSION_MAX - 1;
            }
        }
        e = &list[slot];
    }

    memset(e, 0, sizeof(*e));
    e->used = 1;
    e->sid = sid;
    e->leader_start = leader_start;
    snprintf(e->binary, sizeof(e->binary), "%s", binary);
    if (bin_sha512)
        snprintf(e->binary_sha512, sizeof(e->binary_sha512), "%s", bin_sha512);
    snprintf(e->target, sizeof(e->target), "%s", target);
    if (ttl_seconds > 0)
        e->expiry = mono_seconds() + ttl_seconds;
}

void session_allow_add(pid_t sid, unsigned long long leader_start,
                       const char *binary, const char *bin_sha512,
                       const char *target, int ttl_seconds)
{
    list_add(g_allow, &g_allow_count, sid, leader_start, binary, bin_sha512,
             target, ttl_seconds);
}

void session_deny_add(pid_t sid, unsigned long long leader_start,
                      const char *binary, const char *bin_sha512,
                      const char *target, int ttl_seconds)
{
    list_add(g_deny, &g_deny_count, sid, leader_start, binary, bin_sha512,
             target, ttl_seconds);
}

void session_clear(void)
{
    memset(g_allow, 0, sizeof(g_allow));
    memset(g_deny, 0, sizeof(g_deny));
    g_allow_count = 0;
    g_deny_count = 0;
}
