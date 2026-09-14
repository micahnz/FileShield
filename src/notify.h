#ifndef FILESHIELD_NOTIFY_H
#define FILESHIELD_NOTIFY_H

#include <sys/types.h>

/* Return values for notify_ask(). */
#define NOTIFY_ALLOW_ONCE 0    /* grant access for the configured TTL       */
#define NOTIFY_DENY 1          /* block access this time                     */
#define NOTIFY_ALLOW_SESSION 2 /* grant for the caller's session (shell)     */

/*
 * Store the fanotify fd so notify_ask() can pump pending events while the
 * dialog child is running (prevents dialog deadlock on mount-marked FSes).
 */
void notify_set_fan_fd(int fd);

int notify_ask(const char *comm, pid_t pid, pid_t ppid,
               const char *comm_parent, const char *exe,
               const char *cmdline, const char *path, uid_t user_uid);

#endif
