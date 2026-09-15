#ifndef FILESHIELD_UTILS_H
#define FILESHIELD_UTILS_H

#include <sys/types.h>

extern int g_foreground;

char *proc_exe_path(pid_t pid);
void log_msg(int priority, const char *fmt, ...);

/*
 * proc_stat_session: read /proc/<pid>/stat once and extract the POSIX
 * session id (field 6) and the process start time (field 22, clock ticks
 * since boot).  Either out pointer may be NULL.  Returns 0 on success,
 * -1 when the process is gone or the stat line cannot be parsed; out
 * values stay untouched on failure.  Shared by cache.c (PID-reuse
 * detection) and session.c (session identity) — one parser instead of
 * two divergent ones.
 */
int proc_stat_session(pid_t pid, unsigned long long *sid_out,
                      unsigned long long *start_out);

/*
 * close_fds_from: close every file descriptor >= 'first' in the calling
 * process.  Used by fork()ed children before exec() so no daemon file
 * descriptors (fanotify group fd, event fds, pipes) leak into helpers.
 * Uses close_range(2) when available and falls back to a bounded loop.
 */
void close_fds_from(int first);

/*
 * path_under: return 1 if 'path' is equal to or inside 'dir'.
 * Not used in the fanotify event loop (marks already target specific paths),
 * but available for tests and future callers.
 */
int path_under(const char *path, const char *dir);

/*
 * expand_home_all_users: expand a ~/... path template for every user in
 * /etc/passwd and return a NULL-terminated array of malloc'd strings.
 * For paths that do not start with ~/ the array contains a single copy.
 * Returns NULL on allocation failure.  Caller must call free_string_array().
 */
char **expand_home_all_users(const char *path);
void free_string_array(char **arr);

#endif
