#ifndef FILESHIELD_SESSION_H
#define FILESHIELD_SESSION_H

#include <sys/types.h>

/*
 * In-memory session-scoped allow/deny decisions.
 *
 * A "session" is the POSIX session (setsid(2)) the requesting process
 * belongs to -- for an interactive shell that is the shell itself, so a
 * new terminal window/tab is a new session and closing the shell ends it.
 * Entries are never persisted: a daemon restart clears them (fail closed,
 * the user is re-prompted).
 */

/*
 * Resolve the POSIX session id for pid and the start time of the session
 * leader (/proc/<sid>/stat field 22).  The start time guards against a
 * recycled SID being mistaken for the original session.  Either out
 * pointer may be NULL.  Returns 0 on success, -1 on failure.
 */
int session_id_of(pid_t pid, pid_t *sid_out, unsigned long long *leader_start_out);

/*
 * Record a session-scoped decision.  ttl_seconds == 0 means the entry is
 * valid for as long as the session leader lives; > 0 caps its lifetime in
 * seconds as well.  The target file is mandatory (an empty target never
 * matches) and a binary SHA-512 is compared whenever one was recorded.
 */
void session_allow_add(pid_t sid, unsigned long long leader_start,
                       const char *binary, const char *bin_sha512,
                       const char *target, int ttl_seconds);
void session_deny_add(pid_t sid, unsigned long long leader_start,
                      const char *binary, const char *bin_sha512,
                      const char *target, int ttl_seconds);

/*
 * Match a session-scoped entry.  Returns 1 on match, 0 otherwise.
 * If the entry recorded a binary SHA-512 and the caller cannot provide
 * one, the entry does not match (fail closed: re-prompt).  A match also
 * lazily drops entries whose leader exited, whose start time changed, or
 * whose TTL expired.
 */
int session_allow_match(pid_t sid, const char *binary, const char *bin_sha512,
                        const char *target);
int session_deny_match(pid_t sid, const char *binary, const char *bin_sha512,
                       const char *target);

/* Remove every entry (tests / shutdown). */
void session_clear(void);

#endif
