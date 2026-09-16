/*
 * SIGHUP reload and mark installation.
 *
 * Moved out of main.c so the reject/rollback/shutdown decision paths can
 * be unit-tested with fan_fd = -1 (every kernel mark fails there), without
 * a fanotify group or root.
 */
#include <signal.h>
#include <stdlib.h>
#include <syslog.h>

#include "reload.h"
#include "cache.h"
#include "fanotify.h"
#include "persist.h"
#include "pin.h"
#include "utils.h"

/* Defined in main.c; the reload path reads and clears them. */
extern volatile sig_atomic_t g_need_reload;
extern volatile sig_atomic_t g_fatal;

int install_marks(int fan_fd, const Config *cfg, const char *phase,
                  int *skipped)
{
    int failures = 0;

    *skipped = 0;
    for (int i = 0; i < cfg->protected_count; i++)
    {
        int rc = fanotify_add_protected(fan_fd, &cfg->protected[i]);
        if (rc < 0)
        {
            log_msg(LOG_ERR, "%s: failed to add mark for %s", phase,
                    cfg->protected[i].path);
            failures++;
        }
        else if (rc > 0)
            (*skipped)++;
    }
    return failures;
}

/*
 * Load one persisted runtime list.  A missing, corrupt or unreadable file
 * clears the in-memory list rather than keeping stale grants (fail
 * secure), so the loader runs even when the file yields zero entries.
 */
static void load_persist_list(const char *path,
                              void (*apply)(const PersistEntry *, int))
{
    PersistEntry *buf = calloc(PERSIST_MAX_ENTRIES, sizeof(PersistEntry));
    if (!buf)
    {
        log_msg(LOG_WARNING,
                "out of memory loading %s; clearing the in-memory list", path);
        apply(NULL, 0);
        return;
    }
    int n = persist_load(path, buf, PERSIST_MAX_ENTRIES);
    apply(buf, n < 0 ? 0 : n);
    free(buf);
}

void load_persisted_state(void)
{
    load_persist_list(PERSIST_STATE_FILE, fanotify_load_dyn_allowlist);
    load_persist_list(PERSIST_DENY_STATE_FILE, fanotify_load_dyn_denylist);
}

void load_pin_state(void)
{
    pin_load(PIN_STATE_FILE);
}

int reload_protection(int fan_fd, const char *config_path, Config **cfg)
{
    g_need_reload = 0;
    log_msg(LOG_INFO, "reloading config");

    Config *new_cfg = calloc(1, sizeof(Config));
    if (!new_cfg)
    {
        log_msg(LOG_ERR, "out of memory during reload, keeping old config");
        load_persisted_state();
        load_pin_state();
        cache_expire();
        return 0;
    }

    if (config_load(config_path, new_cfg) != 0)
    {
        log_msg(LOG_ERR, "config reload failed, keeping old config");
        free(new_cfg);
        load_persisted_state();
        load_pin_state();
        cache_expire();
        return 0;
    }

    /* Publish the new config before anything consults it: both the scope
     * guard and the inode walk read g_config, and no event is processed
     * until this function returns. */
    g_config = new_cfg;

    if (fanotify_scope_guard(config_path) < 0)
    {
        log_msg(LOG_ERR,
                "reload rejected by the scope guard; keeping old config");
        g_config = *cfg;
        free(new_cfg);
        load_persisted_state();
        load_pin_state();
        cache_expire();
        return 0;
    }

    /* clear_marks() removes every mark the daemon installed (including
     * auto-added directory marks) with the exact masks they were added
     * with, so the new config rebuilds the mark set from scratch. */
    fanotify_clear_marks(fan_fd);

    int skipped = 0;
    int failures = install_marks(fan_fd, new_cfg, "reload", &skipped);

    /* Fail closed: never leave the daemon partially or fully
     * unprotected.  A failed (or protection-less) reload rolls back to
     * the previous mark set and keeps the old config; if even that
     * cannot be restored, shut down so systemd restarts from a clean
     * state.  Config paths that do not exist yet (rc 1) are skipped,
     * not fatal. */
    if (failures > 0 ||
        new_cfg->protected_count - new_cfg->exclude_count <= 0 ||
        !fanotify_any_mark_active())
    {
        log_msg(LOG_ERR,
                "reload rejected (%d mark failures, %d protected paths, "
                "%d exclusions); restoring previous protection",
                failures, new_cfg->protected_count - new_cfg->exclude_count,
                new_cfg->exclude_count);

        /* Rebuild from a clean slate: the partially installed new marks
         * must be removed before the previous set is restored, and the
         * old config has to be published first so the rollback walk
         * records inodes against the old exclusion list.  g_config never
         * points at new_cfg after it is freed below. */
        fanotify_clear_marks(fan_fd);
        g_config = *cfg;

        int rollback_skipped = 0;
        if (install_marks(fan_fd, *cfg, "rollback", &rollback_skipped) > 0)
        {
            log_msg(LOG_ERR, "rollback failed; shutting down");
            g_fatal = 1;
        }

        free(new_cfg);

        load_persisted_state();
        load_pin_state();
        cache_expire();
        return g_fatal ? -1 : 0;
    }

    log_msg(LOG_INFO,
            "config reloaded, watching %d paths (%d exclusions, "
            "%d missing, covered by mount marks)",
            new_cfg->protected_count - new_cfg->exclude_count,
            new_cfg->exclude_count, skipped);
    free(*cfg);
    *cfg = new_cfg;
    g_config = *cfg;

    load_persisted_state();
    load_pin_state();
    cache_expire();
    return 0;
}
