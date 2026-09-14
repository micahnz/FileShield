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
 * Event mask used for file and directory marks.  Directory-entry events
 * (FAN_CREATE, FAN_DELETE, FAN_MOVED_FROM, FAN_MOVED_TO, FAN_ATTRIB,
 * FAN_DELETE_SELF) require a group initialized with FAN_REPORT_FID and
 * make fanotify_mark() fail with EINVAL on this fd-based group, so they
 * must never be added here.  Exposed for the unprivileged regression test.
 */
unsigned int fanotify_mark_mask(void);

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
 * Queue a read-but-undecided permission event for replay by the main
 * loop; the kernel event fd must stay open.  Returns 0 when queued,
 * -1 when the pending queue is full — the caller must then respond
 * fail-closed (FAN_DENY) and close the event fd.
 */
int fanotify_defer_event(const struct fanotify_event_metadata *ev);

/* Current number of deferred (pending) permission events. */
int fanotify_pending_count(void);

/*
 * Deny and close every deferred permission event.  Called when the
 * kernel reports FAN_Q_OVERFLOW (saturation) and on config reload and
 * shutdown; fail closed.
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
