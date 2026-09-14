#ifndef FILESHIELD_FANOTIFY_H
#define FILESHIELD_FANOTIFY_H

#include <sys/fanotify.h>
#include "persist.h"

int fanotify_setup(void);
int fanotify_add_mark(int fd, const char *path);
int fanotify_remove_mark(int fd, const char *path);
void fanotify_loop(int fd);
int fanotify_respond(int fd, const struct fanotify_event_metadata *ev, unsigned int response);

/*
 * Clear mount marks and inode table before a config reload.
 */
void fanotify_clear_marks(int fd);

/*
 * Drain pending FAN_OPEN_PERM events without blocking.
 * Auto-allows events from the dialog process group (dialog child and its
 * children, e.g. kdialog behind timeout(1)), events from direct daemon
 * children, and non-protected opens.  Events that require a user decision
 * are copied to a deferred queue (their event fd stays open) and are
 * replayed by the main loop once the dialog finishes.  Closing such an
 * event fd instead would leave the caller's open() blocked forever and
 * leak a kernel permission event.
 * Called by notify.c while waiting for the dialog child to finish.
 * Returns the number of events responded to immediately.
 */
int fanotify_pump(int fan_fd, pid_t dialog_child_pid);

/*
 * Deny and close every deferred permission event.  Called on config reload
 * and shutdown; fail closed.
 */
void fanotify_flush_pending(int fan_fd);

/*
 * Dynamic allowlist / denylist management: export the in-memory lists for
 * persistence.
 */

/* Get the current dynamic allowlist entries. Returns count of entries. */
int fanotify_get_dyn_allowlist(PersistEntry *out_entries, int max_entries);

/* Load persisted entries into the dynamic allowlist. Called on daemon startup. */
void fanotify_load_dyn_allowlist(const PersistEntry *entries, int count);

/* Get the current dynamic denylist entries. Returns count of entries. */
int fanotify_get_dyn_denylist(PersistEntry *out_entries, int max_entries);

/* Load persisted entries into the dynamic denylist. Called on daemon startup. */
void fanotify_load_dyn_denylist(const PersistEntry *entries, int count);

#endif
