#ifndef FILESHIELD_CACHE_H
#define FILESHIELD_CACHE_H

#include <sys/types.h>

/*
 * Decision cache.  Entries have one of two scopes:
 *
 *  - PID scope (cache_insert): matches exactly one process instance
 *    (pid + /proc start time) and the binary path.  Backs "Allow Once".
 *
 *  - SESSION scope (cache_insert_session): matches every descendant of a
 *    grant root process (the caller's session leader, e.g. the terminal
 *    shell, or its parent) as long as that process is alive and the
 *    binary identity (dev/ino/size/mtime) is unchanged.  Backs
 *    "Allow Session".  ttl_seconds == 0 means the grant lasts until the
 *    root exits; a positive value caps it in time.
 *
 * cache_lookup checks both scopes and returns remaining TTL seconds (>0),
 * or 0 when no entry matches.
 */
int  cache_lookup(pid_t pid, const char *binary);

/* Grant the exact process instance for ttl_seconds (must be > 0). */
void cache_insert(pid_t pid, const char *binary, int ttl_seconds);

/*
 * Grant the caller's session subtree for binary.  Returns 0 on success,
 * -1 when the grant could not be recorded (no verifiable ancestry or
 * binary identity), in which case the next access will re-prompt.
 */
int  cache_insert_session(pid_t pid, const char *binary, int ttl_seconds);

void cache_expire(void);
int  cache_entry_count(void);

#endif
