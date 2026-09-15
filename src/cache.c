#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <unistd.h>

#include "cache.h"

#define CACHE_MAX_ENTRIES 4096

/*
 * Upper bound for any cached decision (1 year): keeps `now + ttl` safe
 * even with 32-bit time_t and bounds how long a grant can outlive a
 * policy change.  config.c clamps at parse time with a warning; this is
 * the defensive backstop (cache.c stays standalone for unit tests).
 */
#define CACHE_MAX_TTL_SECONDS (365 * 24 * 60 * 60)

typedef struct
{
    pid_t pid;
    unsigned long long starttime; /* /proc/<pid>/stat field 22; 0 = unknown */
    char binary_path[PATH_MAX];
    char target_path[PATH_MAX];   /* "" = wildcard (any file)             */
    time_t expiry_time;
} cache_entry_t;

static cache_entry_t cache[CACHE_MAX_ENTRIES];
static int cache_initialized = 0;

static void cache_init(void)
{
    memset(cache, 0, sizeof(cache));
    cache_initialized = 1;
}

/*
 * Read the process start time (field 22 of /proc/<pid>/stat, in clock
 * ticks since boot).  Returns 0 when it cannot be determined; callers
 * treat 0 as "unknown" and only match other unknown values, so a PID
 * that cannot be verified is never silently trusted.
 */
static unsigned long long proc_start_time(pid_t pid)
{
    char path[64];
    char buf[1024];
    FILE *f;
    size_t n;

    snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
    f = fopen(path, "r");
    if (!f)
        return 0;
    n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (n == 0)
        return 0;
    buf[n] = '\0';

    /* The comm field may contain spaces and parentheses: skip past the
     * last ')' to reach the fixed numeric fields. */
    char *q = strrchr(buf, ')');
    if (!q)
        return 0;
    q++;
    while (*q == ' ')
        q++;
    if (*q == '\0')
        return 0;
    q++; /* skip the single-character state field (field 3) */

    unsigned long long value = 0;
    /* Read fields 4..22; the last one is starttime. */
    for (int i = 4; i <= 22; i++)
    {
        char *endp;
        while (*q == ' ')
            q++;
        value = strtoull(q, &endp, 10);
        if (endp == q)
            return 0;
        q = endp;
    }
    return value;
}

int cache_lookup(pid_t pid, const char *binary, const char *target)
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

        /* Reject a different process that reused the same PID. */
        if (cache[i].starttime != proc_start_time(pid))
        {
            cache[i].pid = 0;
            return 0;
        }

        if (cache[i].expiry_time < now)
        {
            cache[i].pid = 0;
            return 0;
        }

        return (int)(cache[i].expiry_time - now);
    }

    return 0;
}

void cache_insert(pid_t pid, const char *binary, const char *target,
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
    if (ttl_seconds > CACHE_MAX_TTL_SECONDS)
        ttl_seconds = CACHE_MAX_TTL_SECONDS;

    /* Normalise NULL and "" to the wildcard representation. */
    tgt = (target && target[0] != '\0') ? target : "";

    now = time(NULL);

    for (i = 0; i < CACHE_MAX_ENTRIES; i++)
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

    if (free_slot < 0)
        return;

    cache[free_slot].pid = pid;
    cache[free_slot].starttime = proc_start_time(pid);
    strncpy(cache[free_slot].binary_path, binary, PATH_MAX - 1);
    cache[free_slot].binary_path[PATH_MAX - 1] = '\0';
    strncpy(cache[free_slot].target_path, tgt, PATH_MAX - 1);
    cache[free_slot].target_path[PATH_MAX - 1] = '\0';
    cache[free_slot].expiry_time = now + ttl_seconds;
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
        if (cache[i].pid == 0)
            continue;
        if (cache[i].expiry_time < now)
            cache[i].pid = 0;
    }
}
