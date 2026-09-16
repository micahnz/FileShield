#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <syslog.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>

#include "utils.h"
#include "config.h"
#include "fanotify.h"
#include "notify.h"
#include "reload.h"

#define DEFAULT_CONFIG "/etc/fileshield.conf"

volatile sig_atomic_t g_running = 1;
volatile sig_atomic_t g_need_reload = 0;
volatile sig_atomic_t g_fatal = 0;

/* Signal-wake pipe: the handlers write one byte so fanotify_loop()'s
 * poll() observes a signal that arrives even between its flag check and
 * the poll() call.  O_NONBLOCK: the write must never block a handler;
 * a full pipe is harmless because the flag is already set.  O_CLOEXEC:
 * the fd must not leak into the dialog child or any helper. */
static int g_sigwake[2] = {-1, -1};

/* write() is async-signal-safe; (void)r silences the unused-result warn
 * without branching in the handler. */
static void sigwake(char tag)
{
    if (g_sigwake[1] >= 0)
    {
        ssize_t r = write(g_sigwake[1], &tag, 1);
        (void)r;
    }
}

static void sigterm_handler(int sig)
{
    (void)sig;
    g_running = 0;
    sigwake('S');
}

static void sighup_handler(int sig)
{
    (void)sig;
    g_need_reload = 1;
    sigwake('R');
}

static void print_usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [OPTIONS]\n", prog);
    fprintf(stderr, "  -f, --foreground    Run in foreground (do not daemonize)\n");
    fprintf(stderr, "  -c, --config PATH   Config file path (default: %s)\n", DEFAULT_CONFIG);
    fprintf(stderr, "  -d, --debug         Log per-event debug details\n");
    fprintf(stderr, "  -n, --dry-run       Print the marks the config would install, then exit\n");
    fprintf(stderr, "  -h, --help          Show this help\n");
}

/*
 * Shared startup-failure cleanup: deny whatever the partially installed
 * marks already queued (the kernel would auto-allow outstanding
 * permission events on close), then close the group fd, drop the config
 * and close syslog.  Returns EXIT_FAILURE so call sites can
 * `return startup_fail(...)`.
 */
static int startup_fail(int fan_fd, Config *cfg)
{
    if (fan_fd >= 0)
    {
        fanotify_flush_pending(fan_fd);
        fanotify_drain_and_deny(fan_fd);
        close(fan_fd);
    }
    config_reset(cfg);
    free(cfg);
    closelog();
    return EXIT_FAILURE;
}

static void daemonize(void)
{
    /* Detach from the invoking directory and tighten the file-creation
     * mask: a daemon must not pin a mount point or create world-readable
     * files when started by hand (the systemd unit also sets UMask=0077).
     * A relative --config has been resolved to an absolute path by the
     * caller (failure is fatal there). */
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

int main(int argc, char *argv[])
{
    const char *config_path = DEFAULT_CONFIG;
    int dry_run = 0;

    static struct option long_opts[] = {
        {"foreground", no_argument, 0, 'f'},
        {"config", required_argument, 0, 'c'},
        {"debug", no_argument, 0, 'd'},
        {"dry-run", no_argument, 0, 'n'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}};

    int opt;
    while ((opt = getopt_long(argc, argv, "fc:dhn", long_opts, NULL)) != -1)
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
        case 'n':
            dry_run = 1;
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
        return startup_fail(-1, cfg);
    }
    g_config = cfg;

    if (dry_run)
    {
        int guard = fanotify_scope_guard(config_path);

        printf("scope guard: %s\n", guard == 0 ? "ok" : "REFUSED");
        fanotify_dry_run(cfg);
        config_reset(cfg);
        free(cfg);
        closelog();
        return guard == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    if (!g_foreground)
    {
        /* daemonize() chdir()s to /, so a relative --config must be made
         * absolute now: a SIGHUP reload would otherwise resolve it from
         * the wrong directory and keep the old config forever.  The
         * config loaded successfully, so the file exists — a realpath
         * failure here (EACCES on a parent, ELOOP) is a known
         * inconsistency and a silent reload breakage, hence fatal. */
        if (config_path[0] != '/')
        {
            static char config_abs[PATH_MAX];
            if (!realpath(config_path, config_abs))
            {
                log_msg(LOG_ERR,
                        "cannot resolve --config %s: %s (a relative path "
                        "would break reload after daemonize)",
                        config_path, strerror(errno));
                return startup_fail(-1, cfg);
            }
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

    /* The wake pipe must exist before the loop starts polling.  Failure
     * degrades to the old behavior (poll(2) still returns EINTR for a
     * signal delivered mid-call), so warn and continue rather than
     * refuse to start over a pipe. */
    if (pipe2(g_sigwake, O_CLOEXEC | O_NONBLOCK) < 0)
    {
        g_sigwake[0] = g_sigwake[1] = -1;
        log_msg(LOG_WARNING,
                "signal wake pipe unavailable: %s (shutdown may lag on an "
                "idle filesystem)",
                strerror(errno));
    }

    int fan_fd = fanotify_setup();
    if (fan_fd < 0)
    {
        log_msg(LOG_ERR, "fanotify_setup failed");
        return startup_fail(-1, cfg);
    }
    notify_set_fan_fd(fan_fd);

    /* Fail closed: a security daemon must never run in a silently
     * degraded state.  Any path we could not mark would be unprotected
     * while the user believes it is watched, so startup aborts and
     * systemd's Restart=always retries it. */
    if (cfg->protected_count - cfg->exclude_count <= 0)
    {
        log_msg(LOG_ERR,
                "no protected paths configured (exclusions alone do not "
                "protect); refusing to start");
        return startup_fail(fan_fd, cfg);
    }
    /* Refuse a config whose own state/config files the marks would
     * intercept (self-deadlock class). */
    if (fanotify_scope_guard(config_path) < 0)
        return startup_fail(fan_fd, cfg);

    int mark_skipped = 0;

    /* Load persisted "Always Allow"/"Always Deny" entries and the hash
     * pins BEFORE installing marks: while marks are active, an open() of
     * these state files could be answered only by the daemon itself.  A
     * read error is treated as an empty list (fail secure); the state is
     * reloaded on SIGHUP as well. */
    load_persisted_state();
    load_pin_state();

    int mark_failures = install_marks(fan_fd, cfg, "startup", &mark_skipped);
    if (mark_failures > 0)
    {
        log_msg(LOG_ERR,
                "%d of %d protected paths could not be marked; refusing to "
                "start with incomplete protection",
                mark_failures, cfg->protected_count);
        return startup_fail(fan_fd, cfg);
    }

    /* Fail closed if nothing at all is being watched: every configured
     * path was missing and no filesystem could be mount-marked either. */
    if (!fanotify_any_mark_active())
    {
        log_msg(LOG_ERR,
                "no protected path could be marked on any filesystem; "
                "refusing to start");
        return startup_fail(fan_fd, cfg);
    }

    if (mark_skipped > 0)
        log_msg(LOG_WARNING,
                "%d protected path(s) do not exist yet; they are covered by "
                "the filesystem mount mark if created later (reload for a "
                "direct mark)",
                mark_skipped);

    log_msg(LOG_INFO, "Fileshield started, watching %d paths (%d exclusions)",
            cfg->protected_count - cfg->exclude_count, cfg->exclude_count);

    while (g_running)
    {
        fanotify_loop(fan_fd, g_sigwake[0]);
        if (g_fatal)
            break;
        if (g_need_reload && reload_protection(fan_fd, config_path, &cfg) < 0)
            break;
    }

    log_msg(LOG_INFO, "Fileshield shutting down");
    /* Fail closed: the kernel allows outstanding permission events when
     * the group fd is closed, so deny the userspace-deferred queue and
     * everything still queued in the kernel before close(fan_fd). */
    fanotify_flush_pending(fan_fd);
    fanotify_drain_and_deny(fan_fd);
    close(fan_fd);
    /* Clear the globals before closing: a signal landing after the close
     * must not make the handler write into a recycled descriptor. */
    if (g_sigwake[0] >= 0 || g_sigwake[1] >= 0)
    {
        int rfd = g_sigwake[0];
        int wfd = g_sigwake[1];
        g_sigwake[0] = -1;
        g_sigwake[1] = -1;
        if (rfd >= 0)
            close(rfd);
        if (wfd >= 0)
            close(wfd);
    }
    config_reset(cfg);
    free(cfg);
    closelog();
    return g_fatal ? EXIT_FAILURE : EXIT_SUCCESS;
}
