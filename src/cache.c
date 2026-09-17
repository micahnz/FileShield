#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <unistd.h>

#include "cache.h"
#include "utils.h"

#define CACHE_MAX_ENTRIES 4096

typedef struct
{
    pid_t pid;
    unsigned long long starttime; /* /proc/<pid>/stat field 22; 0 = unknown */
    char binary_path[PATH_MAX];
    char target_path[PATH_MAX];   /* "" = wildcard (any file)             */
    time_t expiry_time;           /* mono_seconds() deadline; 0 = none    */
} cache_entry_t;

static cache_entry_t cache[CACHE_MAX_ENTRIES];
static int cache_initialized = 0;

/*
 * High-water mark: one past the highest slot ever used.  Lookups and
 * inserts only need to scan live slots, not all 4096; the mark never
 * shrinks (expired slots are skipped on one cheap pid==0 compare), which
 * keeps every code path trivially correct.  Baseline for this change was
 * 5.24 us per miss-scan over the full table at 128 live entries
 * (tests/bench_hotpath.c); the mark bounds the miss scan by the number
 * of slots ever touched instead of the table size.
 */
static int cache_high = 0;

static void cache_init(void)
{
    memset(cache, 0, sizeof(cache));
    cache_initialized = 1;
    cache_high = 0;
}

/*
 * Read the process start time (field 22 of /proc/<pid>/stat, in clock
 * ticks since boot).  Returns 0 when it cannot be determined.  An entry
 * whose start time is unknown only matches a lookup whose start time is
 * also unknown: for both sides to be 0, /proc must have been unreadable
 * at insert and at lookup, and the entry is still pid/path/TTL-scoped.
 */
static unsigned long long proc_start_time(pid_t pid)
{
    unsigned long long start = 0;
    (void)proc_stat_session(pid, NULL, &start);
    return start;
}

int cache_lookup(pid_t pid, const char *binary, const char *target)
{
    time_t now;
    int i;

    if (!binary)
        return 0;

    if (!cache_initialized)
        cache_init();

    now = mono_seconds();

    for (i = 0; i < cache_high; i++)
    {
        if (cache[i].pid == 0)
            continue;
        if (cache[i].pid != pid)
            continue;
        if (strcmp(cache[i].binary_path, binary) != 0)
            continue;

        /* Wildcard entries (config [allowlist] hits) cover every target;
         * a file-scoped entry must match the requested path exactly. */
        if (cache[i].target_path[0] != '\0' &&
            (!target || strcmp(cache[i].target_path, target) != 0))
            continue;

        /* Reject a different process that reused the same PID, and drop
         * an expired entry: later entries for the same (pid, binary) may
         * still cover the request (file-scoped vs wildcard), so keep
         * scanning instead of reporting a miss. */
        if (cache[i].starttime != proc_start_time(pid))
        {
            cache[i].pid = 0;
            continue;
        }

        if (cache[i].expiry_time < now)
        {
            cache[i].pid = 0;
            continue;
        }

        return (int)(cache[i].expiry_time - now);
    }

    return 0;
}

/*
 * Insert (or refresh) an entry with an explicit start time.  cache_insert()
 * fills it from /proc; the test seam injects it so PID-reuse rejection can
 * be exercised without a recycled PID.
 */
static void cache_insert_starttime(pid_t pid, unsigned long long starttime,
                                   const char *binary, const char *target,
                                   int ttl_seconds)
{
    time_t now;
    int i;
    int free_slot = -1;
    const char *tgt;

    if (!cache_initialized)
        cache_init();

    if (binary == NULL)
        return;

    if (ttl_seconds <= 0)
        return;
    if (ttl_seconds > FS_MAX_TTL_SECONDS)
        ttl_seconds = FS_MAX_TTL_SECONDS;

    /* Normalise NULL and "" to the wildcard representation. */
    tgt = (target && target[0] != '\0') ? target : "";

    now = mono_seconds();

    for (i = 0; i < cache_high; i++)
    {
        if (cache[i].pid != 0)
        {
            if (cache[i].pid == pid && strcmp(cache[i].binary_path, binary) == 0 &&
                strcmp(cache[i].target_path, tgt) == 0)
            {
                free_slot = i;
                break;
            }
            continue;
        }
        if (free_slot < 0)
            free_slot = i;
    }

    /* Beyond the high-water mark every slot is free: the first one wins
     * without scanning. */
    if (free_slot < 0 && cache_high < CACHE_MAX_ENTRIES)
        free_slot = cache_high;

    if (free_slot < 0)
        return; /* table full: no eviction policy, drop the insert */

    if (free_slot >= cache_high)
        cache_high = free_slot + 1;

    cache[free_slot].pid = pid;
    cache[free_slot].starttime = starttime;
    strncpy(cache[free_slot].binary_path, binary, PATH_MAX - 1);
    cache[free_slot].binary_path[PATH_MAX - 1] = '\0';
    strncpy(cache[free_slot].target_path, tgt, PATH_MAX - 1);
    cache[free_slot].target_path[PATH_MAX - 1] = '\0';
    cache[free_slot].expiry_time = now + ttl_seconds;
}

void cache_insert(pid_t pid, const char *binary, const char *target,
                  int ttl_seconds)
{
    cache_insert_starttime(pid, proc_start_time(pid), binary, target,
                           ttl_seconds);
}

void cache_test_insert_with_starttime(pid_t pid, unsigned long long starttime,
                                      const char *binary, const char *target,
                                      int ttl_seconds)
{
    cache_insert_starttime(pid, starttime, binary, target, ttl_seconds);
}

void cache_expire(void)
{
    time_t now;
    int i;

    if (!cache_initialized)
        cache_init();

    now = mono_seconds();

    for (i = 0; i < cache_high; i++)
    {
        if (cache[i].pid == 0)
            continue;
        if (cache[i].expiry_time < now)
            cache[i].pid = 0;
    }
}

void cache_clear(void)
{
    if (!cache_initialized)
        cache_init();
    else
        memset(cache, 0, sizeof(cache));
    cache_high = 0; /* empty table: restart the scan bound at zero */
}

