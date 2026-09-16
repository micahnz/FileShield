#ifndef FILESHIELD_RELOAD_H
#define FILESHIELD_RELOAD_H

#include "config.h"

/*
 * Install a mark for every configured positive protected path
 * (exclusions are never marked; fanotify_add_protected returns 0 for
 * them).  Returns the number of real failures; paths that do not exist
 * yet (rc 1) are counted in *skipped.  Callers treat any failure as fatal
 * (fail closed).
 */
int install_marks(int fan_fd, const Config *cfg, const char *phase,
                  int *skipped);

/* Load both persisted "Always" lists (startup and every reload). */
void load_persisted_state(void);

/*
 * Load the [allowlist] hash pins (startup and every reload).  A missing
 * file is normal first use; a damaged or unreadable one leaves the table
 * untrusted (fail closed).
 */
void load_pin_state(void);

/*
 * Re-register protection after SIGHUP: parse the new config, replace the
 * marks, and roll back to the previous mark set if the new one cannot be
 * installed completely.  Returns 0 to continue, -1 when the daemon must
 * shut down (rollback failed; systemd restarts from a clean state).
 *
 * Lives outside main.c so the decision paths are unit-testable: with
 * fan_fd = -1 every kernel mark fails, which drives the parse-failure,
 * reject-plus-rollback and rollback-failure branches without privileges.
 */
int reload_protection(int fan_fd, const char *config_path, Config **cfg);

#endif
