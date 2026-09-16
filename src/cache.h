#ifndef FILESHIELD_CACHE_H
#define FILESHIELD_CACHE_H

#include <sys/types.h>

/*
 * PID-keyed allow cache with TTL.
 *
 * Entries are scoped to a target file: an entry inserted with a concrete
 * target only matches lookups for that exact path, while an entry inserted
 * with target == NULL (or "") is a wildcard that matches any file.  The
 * wildcard form is used for config [allowlist] hits, which grant a binary
 * access to every protected path; user "Allow Once" decisions are always
 * file-scoped.
 */

/* Returns remaining TTL seconds (> 0) when the cache covers this
 * (pid, binary, target), or 0 when absent/expired/unrelated. */
int  cache_lookup(pid_t pid, const char *binary, const char *target);

/* Insert (or refresh) an entry.  target == NULL means "any file". */
void cache_insert(pid_t pid, const char *binary, const char *target,
                  int ttl_seconds);

void cache_expire(void);

/*
 * Test seam: insert with an explicit process start time so PID-reuse
 * rejection can be exercised without a recycled PID.  starttime == 0
 * means "unknown".
 */
void cache_test_insert_with_starttime(pid_t pid, unsigned long long starttime,
                                      const char *binary, const char *target,
                                      int ttl_seconds);

#endif
