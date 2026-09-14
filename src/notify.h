#ifndef FILESHIELD_NOTIFY_H
#define FILESHIELD_NOTIFY_H

#include <sys/types.h>

/* Return values for notify_ask(). */
#define NOTIFY_ALLOW_ONCE 0    /* cache this file for the process (user_ttl) */
#define NOTIFY_DENY 1          /* block this attempt only                     */
#define NOTIFY_ALLOW_ALWAYS 2  /* persistent runtime allowlist entry          */
#define NOTIFY_DENY_ALWAYS 3   /* persistent runtime denylist entry           */
#define NOTIFY_ALLOW_SESSION 4 /* allow this file until the session ends      */
#define NOTIFY_DENY_SESSION 5  /* deny this file until the session ends       */

/*
 * Store the fanotify fd so notify_ask() can pump pending events while the
 * dialog child is running (prevents dialog deadlock on mount-marked FSes).
 */
void notify_set_fan_fd(int fd);

int notify_ask(const char *comm, pid_t pid, pid_t ppid,
               const char *comm_parent, const char *exe,
               const char *cmdline, const char *path, uid_t user_uid);

#endif
