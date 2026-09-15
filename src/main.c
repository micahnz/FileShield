#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <getopt.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>

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
    fprintf(stderr, "  -d, --debug         Log per-event debug details\n");
    fprintf(stderr, "  -h, --help          Show this help\n");
}

static void daemonize(void)
{
    /* Detach from the invoking directory and tighten the file-creation
     * mask: a daemon must not pin a mount point or create world-readable
     * files when started by hand (the systemd unit also sets UMask=0077).
     * A relative --config is resolved by the caller before this runs. */
    if (chdir("/") < 0)
        log_msg(LOG_WARNING, "daemonize: chdir /: %s", strerror(errno));
    umask(0077);

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

/*
 * Install a mark for every configured protected path.  Returns the number
 * of real failures; paths that do not exist yet (rc 1) are counted in
 * *skipped — a filesystem mount mark covers them if they appear later.
 * Callers treat any failure as fatal (fail closed).
 */
static int install_marks(int fan_fd, const Config *cfg, const char *phase,
                         int *skipped)
{
    int failures = 0;

    *skipped = 0;
    for (int i = 0; i < cfg->protected_count; i++)
    {
        int rc = fanotify_add_mark(fan_fd, cfg->protected[i].path);
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

/* Load both persisted "Always" lists (startup and every reload). */
static void load_persisted_state(void)
{
    load_persist_list(PERSIST_STATE_FILE, fanotify_load_dyn_allowlist);
    load_persist_list(PERSIST_DENY_STATE_FILE, fanotify_load_dyn_denylist);
}

/*
 * Re-register protection after SIGHUP: parse the new config, replace the
 * marks, and roll back to the previous mark set if the new one cannot be
 * installed completely.  Returns 0 to continue, -1 when the daemon must
 * shut down (rollback failed; systemd restarts from a clean state).
 */
static int reload_protection(int fan_fd, const char *config_path, Config **cfg)
{
    g_need_reload = 0;
    log_msg(LOG_INFO, "reloading config");

    Config *new_cfg = calloc(1, sizeof(Config));
    if (!new_cfg)
    {
        log_msg(LOG_ERR, "out of memory during reload, keeping old config");
        load_persisted_state();
        cache_expire();
        return 0;
    }

    if (config_load(config_path, new_cfg) != 0)
    {
        log_msg(LOG_ERR, "config reload failed, keeping old config");
        free(new_cfg);
        load_persisted_state();
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
    if (failures > 0 || new_cfg->protected_count == 0 ||
        !fanotify_any_mark_active())
    {
        log_msg(LOG_ERR,
                "reload rejected (%d mark failures, %d paths); "
                "restoring previous protection",
                failures, new_cfg->protected_count);

        int rollback_skipped = 0;
        if (install_marks(fan_fd, *cfg, "rollback", &rollback_skipped) > 0)
        {
            log_msg(LOG_ERR, "rollback failed; shutting down");
            g_fatal = 1;
        }

        /* Republish the old config defensively: g_config must never
         * point at new_cfg after it is freed below.  config_load() no
         * longer publishes, but keep this explicit so a future refactor
         * cannot reintroduce the use-after-free. */
        g_config = *cfg;
        free(new_cfg);

        load_persisted_state();
        cache_expire();
        return g_fatal ? -1 : 0;
    }

    log_msg(LOG_INFO,
            "config reloaded, watching %d paths (%d missing, "
            "covered by mount marks)",
            new_cfg->protected_count, skipped);
    free(*cfg);
    *cfg = new_cfg;
    g_config = *cfg;

    load_persisted_state();
    cache_expire();
    return 0;
}

int main(int argc, char *argv[])
{
    const char *config_path = DEFAULT_CONFIG;

    static struct option long_opts[] = {
        {"foreground", no_argument, 0, 'f'},
        {"config", required_argument, 0, 'c'},
        {"debug", no_argument, 0, 'd'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}};

    int opt;
    while ((opt = getopt_long(argc, argv, "fc:dh", long_opts, NULL)) != -1)
    {
        switch (opt)
        {
        case 'f':
            g_foreground = 1;
            break;
        case 'c':
            config_path = optarg;
            break;
        case 'd':
            log_set_debug(1);
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
    {
        /* daemonize() chdir()s to /, so a relative --config must be made
         * absolute now: a SIGHUP reload would otherwise resolve it from
         * the wrong directory. */
        if (config_path[0] != '/')
        {
            static char config_abs[PATH_MAX];
            if (realpath(config_path, config_abs))
                config_path = config_abs;
        }
        daemonize();
    }

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
    int mark_skipped = 0;
    int mark_failures = install_marks(fan_fd, cfg, "startup", &mark_skipped);
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

    /* Load persisted "Always Allow"/"Always Deny" entries from the
     * previous session.  A read error is treated as an empty list (fail
     * secure). */
    load_persisted_state();

    while (g_running)
    {
        fanotify_loop(fan_fd);
        if (g_fatal)
            break;
        if (g_need_reload && reload_protection(fan_fd, config_path, &cfg) < 0)
            break;
    }

    log_msg(LOG_INFO, "FileShield shutting down");
    fanotify_flush_pending(fan_fd);
    close(fan_fd);
    config_reset(cfg);
    free(cfg);
    closelog();
    return g_fatal ? EXIT_FAILURE : EXIT_SUCCESS;
}
