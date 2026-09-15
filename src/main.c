#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <getopt.h>
#include <errno.h>

#include "utils.h"
#include "config.h"
#include "cache.h"
#include "fanotify.h"
#include "notify.h"
#include "persist.h"

#define DEFAULT_CONFIG "/etc/fileshield.conf"
#define DEFAULT_TTL 300

volatile sig_atomic_t g_running = 1;
volatile sig_atomic_t g_need_reload = 0;
volatile sig_atomic_t g_fatal = 0;

static void sigterm_handler(int sig)
{
    (void)sig;
    g_running = 0;
}

static void sighup_handler(int sig)
{
    (void)sig;
    g_need_reload = 1;
}

static void print_usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [OPTIONS]\n", prog);
    fprintf(stderr, "  -f, --foreground    Run in foreground (do not daemonize)\n");
    fprintf(stderr, "  -c, --config PATH   Config file path (default: %s)\n", DEFAULT_CONFIG);
    fprintf(stderr, "  -h, --help          Show this help\n");
}

static void daemonize(void)
{
    pid_t pid = fork();
    if (pid < 0)
    {
        log_msg(LOG_ERR, "fork failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (pid > 0)
        exit(EXIT_SUCCESS);
    if (setsid() < 0)
    {
        log_msg(LOG_ERR, "setsid failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    /* Second fork: ensure the daemon is not a session leader and cannot
     * re-acquire a controlling terminal (POSIX SUS v3 convention). */
    pid = fork();
    if (pid < 0)
    {
        log_msg(LOG_ERR, "fork (2) failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    if (pid > 0)
        exit(EXIT_SUCCESS);
    /* Redirect stdio into the void.  Failures are deliberately ignored:
     * the daemon writes nothing to stdio (all output goes to syslog), a
     * closed descriptor is still safer than a leaked terminal fd, and
     * aborting daemonization over a redirect failure would leave marks
     * uninstalled. */
    (void)!freopen("/dev/null", "r", stdin);
    (void)!freopen("/dev/null", "w", stdout);
    (void)!freopen("/dev/null", "w", stderr);
}

int main(int argc, char *argv[])
{
    const char *config_path = DEFAULT_CONFIG;

    static struct option long_opts[] = {
        {"foreground", no_argument, 0, 'f'},
        {"config", required_argument, 0, 'c'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}};

    int opt;
    while ((opt = getopt_long(argc, argv, "fc:h", long_opts, NULL)) != -1)
    {
        switch (opt)
        {
        case 'f':
            g_foreground = 1;
            break;
        case 'c':
            config_path = optarg;
            break;
        case 'h':
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        default:
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    openlog("fileshield", LOG_PID | LOG_CONS, LOG_DAEMON);

    Config *cfg = calloc(1, sizeof(Config));
    if (!cfg)
    {
        log_msg(LOG_ERR, "out of memory allocating config");
        return EXIT_FAILURE;
    }
    if (config_load(config_path, cfg) < 0)
    {
        log_msg(LOG_ERR, "failed to load config: %s", config_path);
        free(cfg);
        return EXIT_FAILURE;
    }
    g_config = cfg;

    if (!g_foreground)
        daemonize();

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigterm_handler;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    sa.sa_handler = sighup_handler;
    sigaction(SIGHUP, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    int fan_fd = fanotify_setup();
    if (fan_fd < 0)
    {
        log_msg(LOG_ERR, "fanotify_setup failed");
        free(cfg);
        return EXIT_FAILURE;
    }
    notify_set_fan_fd(fan_fd);

    /* Fail closed: a security daemon must never run in a silently
     * degraded state.  Any path we could not mark would be unprotected
     * while the user believes it is watched, so startup aborts and
     * systemd's Restart=on-failure retries it. */
    if (cfg->protected_count == 0)
    {
        log_msg(LOG_ERR, "no protected paths configured; refusing to start");
        close(fan_fd);
        config_reset(cfg);
        free(cfg);
        closelog();
        return EXIT_FAILURE;
    }
    int mark_failures = 0;
    int mark_skipped = 0;
    for (int i = 0; i < cfg->protected_count; i++)
    {
        int rc = fanotify_add_mark(fan_fd, cfg->protected[i].path);
        if (rc < 0)
        {
            log_msg(LOG_ERR, "failed to add mark for %s", cfg->protected[i].path);
            mark_failures++;
        }
        else if (rc > 0)
        {
            /* Path does not exist yet; the filesystem mount mark covers
             * it if created later. */
            mark_skipped++;
        }
    }
    if (mark_failures > 0)
    {
        log_msg(LOG_ERR,
                "%d of %d protected paths could not be marked; refusing to "
                "start with incomplete protection",
                mark_failures, cfg->protected_count);
        close(fan_fd);
        config_reset(cfg);
        free(cfg);
        closelog();
        return EXIT_FAILURE;
    }

    /* Fail closed if nothing at all is being watched: every configured
     * path was missing and no filesystem could be mount-marked either. */
    if (!fanotify_any_mark_active())
    {
        log_msg(LOG_ERR,
                "no protected path could be marked on any filesystem; "
                "refusing to start");
        close(fan_fd);
        config_reset(cfg);
        free(cfg);
        closelog();
        return EXIT_FAILURE;
    }

    if (mark_skipped > 0)
        log_msg(LOG_WARNING,
                "%d protected path(s) do not exist yet; they are covered by "
                "the filesystem mount mark if created later (reload for a "
                "direct mark)",
                mark_skipped);

    log_msg(LOG_INFO, "FileShield started, watching %d paths", cfg->protected_count);

    /* Load persisted "Always Allow" entries from the previous session.
     * A read error is treated as an empty list (fail secure). */
    {
        PersistEntry *persist_buf = calloc(PERSIST_MAX_ENTRIES, sizeof(PersistEntry));
        if (persist_buf)
        {
            int persist_count = persist_load(PERSIST_STATE_FILE, persist_buf, PERSIST_MAX_ENTRIES);
            fanotify_load_dyn_allowlist(persist_buf, persist_count < 0 ? 0 : persist_count);
            free(persist_buf);
        }
    }

    /* Load persisted "Always Deny" entries from the previous session. */
    {
        PersistEntry *deny_buf = calloc(PERSIST_MAX_ENTRIES, sizeof(PersistEntry));
        if (deny_buf)
        {
            int deny_count = persist_load(PERSIST_DENY_STATE_FILE, deny_buf, PERSIST_MAX_ENTRIES);
            fanotify_load_dyn_denylist(deny_buf, deny_count < 0 ? 0 : deny_count);
            free(deny_buf);
        }
    }

    while (g_running)
    {
        fanotify_loop(fan_fd);
        if (g_fatal)
            break;
        if (g_need_reload)
        {
            g_need_reload = 0;
            log_msg(LOG_INFO, "reloading config");
            Config *new_cfg = calloc(1, sizeof(Config));
            if (!new_cfg)
            {
                log_msg(LOG_ERR, "out of memory during reload, keeping old config");
            }
            else if (config_load(config_path, new_cfg) == 0)
            {
                /* clear_marks() removes every mark the daemon installed
                 * (including auto-added directory marks) with the exact
                 * masks they were added with. */
                fanotify_clear_marks(fan_fd);

                int add_failures = 0;
                int add_skipped = 0;
                for (int i = 0; i < new_cfg->protected_count; i++)
                {
                    int rc = fanotify_add_mark(fan_fd, new_cfg->protected[i].path);
                    if (rc < 0)
                    {
                        log_msg(LOG_ERR, "reload: failed to add mark for %s",
                                new_cfg->protected[i].path);
                        add_failures++;
                    }
                    else if (rc > 0)
                        add_skipped++;
                }

                /* Fail closed: never leave the daemon partially or fully
                 * unprotected.  A failed (or protection-less) reload rolls
                 * back to the previous mark set and keeps the old config;
                 * if even that cannot be restored, shut down so systemd
                 * restarts from a clean state.  Config paths that do not
                 * exist yet (rc 1) are skipped, not fatal. */
                if (add_failures > 0 || new_cfg->protected_count == 0 ||
                    !fanotify_any_mark_active())
                {
                    log_msg(LOG_ERR,
                            "reload rejected (%d mark failures, %d paths); "
                            "restoring previous protection",
                            add_failures, new_cfg->protected_count);
                    for (int i = 0; i < cfg->protected_count; i++)
                    {
                        if (fanotify_add_mark(fan_fd, cfg->protected[i].path) < 0)
                        {
                            log_msg(LOG_ERR,
                                    "rollback failed for %s; shutting down",
                                    cfg->protected[i].path);
                            g_fatal = 1;
                        }
                    }
                    free(new_cfg);
                    if (g_fatal)
                        break;
                }
                else
                {
                    log_msg(LOG_INFO,
                            "config reloaded, watching %d paths (%d missing, "
                            "covered by mount marks)",
                            new_cfg->protected_count, add_skipped);
                    free(cfg);
                    cfg = new_cfg;
                    g_config = cfg;
                }
            }
            else
            {
                log_msg(LOG_ERR, "config reload failed, keeping old config");
                free(new_cfg);
            }
            /* Reload persist files so CLI-managed changes take effect.
             * A missing/corrupt file clears the in-memory list rather
             * than keeping stale grants. */
            {
                PersistEntry *allow_buf = calloc(PERSIST_MAX_ENTRIES, sizeof(PersistEntry));
                if (allow_buf)
                {
                    int n = persist_load(PERSIST_STATE_FILE, allow_buf, PERSIST_MAX_ENTRIES);
                    fanotify_load_dyn_allowlist(allow_buf, n < 0 ? 0 : n);
                    free(allow_buf);
                }
                PersistEntry *deny_buf = calloc(PERSIST_MAX_ENTRIES, sizeof(PersistEntry));
                if (deny_buf)
                {
                    int n = persist_load(PERSIST_DENY_STATE_FILE, deny_buf, PERSIST_MAX_ENTRIES);
                    fanotify_load_dyn_denylist(deny_buf, n < 0 ? 0 : n);
                    free(deny_buf);
                }
            }
            cache_expire();
        }
    }

    log_msg(LOG_INFO, "FileShield shutting down");
    fanotify_flush_pending(fan_fd);
    close(fan_fd);
    config_reset(cfg);
    free(cfg);
    closelog();
    return g_fatal ? EXIT_FAILURE : EXIT_SUCCESS;
}
