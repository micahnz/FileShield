/*
 * test_fanotify: mark mask, bounded event queue + fail-closed saturation
 * handling.
 *
 * Part 0 (runs unprivileged): the mark mask must be free of FID-requiring
 * directory-entry events.  Regression guard for EINVAL on every directory
 * mark when FAN_CREATE/FAN_MOVED_TO were added to this fd-based group.
 *
 * Part 1 (runs unprivileged): the deferred-event boundary.  A pipe stands
 * in for the fanotify group fd — fanotify_respond() only writes a
 * struct fanotify_response to it, so the flush contract (one FAN_DENY
 * response per deferred event, deferred fds closed) is verifiable
 * without a real fanotify group.
 *
 * Part 2 (needs CAP_SYS_ADMIN; skips otherwise): a real kernel fanotify
 * group created WITHOUT FAN_UNLIMITED_QUEUE must report FAN_Q_OVERFLOW
 * once the bounded queue saturates.  This uses notification events only:
 * permission-event saturation cannot be exercised without deliberately
 * blocking a listener, and note that a *bounded* permission queue is
 * fail-open (the kernel drops the event and allows the access), which is
 * why the daemon itself uses FAN_UNLIMITED_QUEUE.
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../src/fanotify.h"
#include "../src/sha512.h"
#include "../src/utils.h"

/* Globals referenced by fanotify.c (normally defined in main.c). */
volatile sig_atomic_t g_running = 1;
volatile sig_atomic_t g_need_reload = 0;
volatile sig_atomic_t g_fatal = 0;

static int failures = 0;

#define ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s\n", (msg)); \
        failures++; \
    } \
} while(0)

/*
 * Part 0: the mark mask must not contain FID-requiring directory-entry
 * events.  Adding FAN_CREATE/FAN_MOVED_TO to a group initialized without
 * FAN_REPORT_FID makes fanotify_mark() fail with EINVAL, which breaks
 * every directory mark (fanotify_mark(2), ERRORS).
 */
static void test_mark_mask_rejects_fid_events(void) {
    const unsigned int mask = fanotify_mark_mask();
    const unsigned int fid_only =
        FAN_CREATE | FAN_DELETE | FAN_MOVED_FROM | FAN_MOVED_TO |
        FAN_ATTRIB | FAN_DELETE_SELF;

    ASSERT((mask & FAN_OPEN_PERM) != 0, "mark mask includes FAN_OPEN_PERM");
    ASSERT((mask & FAN_EVENT_ON_CHILD) != 0,
           "mark mask includes FAN_EVENT_ON_CHILD");
    ASSERT((mask & fid_only) == 0,
           "mark mask contains no FID-requiring dirent events");
}

/*
 * Part 0b: a configured path that does not exist is skipped (returns 1)
 * rather than treated as a fatal mark failure, and skipping registers no
 * mark state.  The default config lists many secrets paths that may not
 * exist on a given machine; those must not crash the daemon.
 */
static void test_missing_path_is_skipped(void) {
    ASSERT(fanotify_any_mark_active() == 0, "no mark state before skip test");
    int rc = fanotify_add_mark(-1, "/nonexistent/fileshield/missing-secret");
    ASSERT(rc == 1, "missing configured path is skipped (rc 1)");
    ASSERT(fanotify_any_mark_active() == 0, "skipped path adds no mark state");

    /* An existing path with an unusable group fd is a real failure. */
    rc = fanotify_add_mark(-1, "/");
    ASSERT(rc == -1, "existing path mark failure is fatal (rc -1)");
    ASSERT(fanotify_any_mark_active() == 0, "failed mark adds no state");
}

/*
 * Part 1b: persisted allow/deny entries are file- and command-scoped.
 * An entry without a target_path or without a command-line fingerprint
 * (legacy or hand-edited state file) must be dropped at load so it cannot
 * act as a wildcard grant or a blanket denial.
 */
static void test_empty_target_entries_dropped(void) {
    const char *sha =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    PersistEntry entries[3];
    memset(entries, 0, sizeof(entries));

    /* Valid file- and command-scoped allow entry. */
    snprintf(entries[0].binary, sizeof(entries[0].binary), "/usr/bin/kubectl");
    snprintf(entries[0].binary_sha512, sizeof(entries[0].binary_sha512), "%s", sha);
    snprintf(entries[0].target_path, sizeof(entries[0].target_path),
             "/home/u/.kube/config");
    snprintf(entries[0].cmdline_sha512, sizeof(entries[0].cmdline_sha512),
             "%s", sha);

    /* Legacy wildcard entry: no target recorded. */
    snprintf(entries[1].binary, sizeof(entries[1].binary), "/usr/bin/ssh");
    snprintf(entries[1].binary_sha512, sizeof(entries[1].binary_sha512), "%s", sha);
    snprintf(entries[1].cmdline_sha512, sizeof(entries[1].cmdline_sha512),
             "%s", sha);

    /* Entry without a command fingerprint: would cover every invocation. */
    snprintf(entries[2].binary, sizeof(entries[2].binary), "/usr/bin/aws");
    snprintf(entries[2].binary_sha512, sizeof(entries[2].binary_sha512), "%s", sha);
    snprintf(entries[2].target_path, sizeof(entries[2].target_path),
             "/home/u/.aws/credentials");

    fanotify_load_dyn_allowlist(entries, 3);

    PersistEntry out[4];
    memset(out, 0, sizeof(out));
    int n = fanotify_get_dyn_allowlist(out, 4);
    ASSERT(n == 1, "entries missing target or command fingerprint are dropped");
    ASSERT(strcmp(out[0].target_path, "/home/u/.kube/config") == 0,
           "remaining allow entry keeps its target");
    ASSERT(strcmp(out[0].cmdline_sha512, sha) == 0,
           "remaining allow entry keeps its command fingerprint");

    /* Denies do not require a binary SHA-512, but require both scopes. */
    PersistEntry dentries[2];
    memset(dentries, 0, sizeof(dentries));
    snprintf(dentries[0].binary, sizeof(dentries[0].binary), "/usr/bin/curl");

    snprintf(dentries[1].binary, sizeof(dentries[1].binary), "/usr/bin/wget");
    snprintf(dentries[1].target_path, sizeof(dentries[1].target_path),
             "/home/u/.netrc");

    fanotify_load_dyn_denylist(dentries, 2);
    memset(out, 0, sizeof(out));
    n = fanotify_get_dyn_denylist(out, 4);
    ASSERT(n == 0, "incomplete deny entries dropped at load");

    /* Reload an empty list so later tests see the daemon's clean state. */
    fanotify_load_dyn_allowlist(NULL, 0);
    fanotify_load_dyn_denylist(NULL, 0);
}

/*
 * Part 1c: permanent entries are scoped to the exact command line.  A
 * grant recorded for "kubectl get pods" must not cover "kubectl get
 * secrets" for the same binary, hash, file and call chain.
 */
static void test_cmdline_scoping(void) {
    const char *sha =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    char cmd_pods[129];
    char cmd_secrets[129];

    ASSERT(sha512_string("kubectl get pods", cmd_pods) == 0,
           "digest of approved command");
    ASSERT(sha512_string("kubectl get secrets", cmd_secrets) == 0,
           "digest of other command");
    ASSERT(strcmp(cmd_pods, cmd_secrets) != 0, "command digests differ");

    PersistEntry e[1];
    memset(e, 0, sizeof(e));
    snprintf(e[0].binary, sizeof(e[0].binary), "/usr/bin/kubectl");
    snprintf(e[0].binary_sha512, sizeof(e[0].binary_sha512), "%s", sha);
    snprintf(e[0].target_path, sizeof(e[0].target_path),
             "/home/u/.kube/config");
    snprintf(e[0].cmdline_sha512, sizeof(e[0].cmdline_sha512), "%s",
             cmd_pods);

    fanotify_load_dyn_allowlist(e, 1);
    ASSERT(fanotify_test_dyn_allow_match("/usr/bin/kubectl", sha,
           "/home/u/.kube/config", "kubectl get pods") == 1,
           "exact command matches the allow entry");
    ASSERT(fanotify_test_dyn_allow_match("/usr/bin/kubectl", sha,
           "/home/u/.kube/config", "kubectl get secrets") == 0,
           "different command does not match the allow entry");
    ASSERT(fanotify_test_dyn_allow_match("/usr/bin/kubectl", sha,
           "/home/u/.ssh/id_rsa", "kubectl get pods") == 0,
           "different target does not match the allow entry");
    ASSERT(fanotify_test_dyn_allow_match("/usr/bin/kubectl", "deadbeef",
           "/home/u/.kube/config", "kubectl get pods") == 0,
           "unverifiable binary hash does not match");
    fanotify_load_dyn_allowlist(NULL, 0);

    /* The deny side mirrors the same scoping. */
    fanotify_load_dyn_denylist(e, 1);
    ASSERT(fanotify_test_dyn_deny_match("/usr/bin/kubectl", sha,
           "/home/u/.kube/config", "kubectl get pods") == 1,
           "exact command matches the deny entry");
    ASSERT(fanotify_test_dyn_deny_match("/usr/bin/kubectl", sha,
           "/home/u/.kube/config", "kubectl get secrets") == 0,
           "different command does not match the deny entry");
    fanotify_load_dyn_denylist(NULL, 0);
}

/*
 * Part 1: fill the deferred queue to capacity, verify a full queue
 * refuses further events, then verify the fail-closed flush denies and
 * closes every deferred event.
 */
static void test_defer_flush_contract(void) {
    /*
     * Pre-warm glibc's lazily-opened /dev/log socket: flush_pending()
     * calls log_msg() after closing the deferred fds, and on first use
     * syslog would otherwise claim the lowest freed fd number — which
     * would make the EBADF close-check below misread that fd as open.
     */
    log_msg(LOG_DEBUG, "warm up syslog socket");

    int resp_pipe[2];
    ASSERT(pipe(resp_pipe) == 0, "create response pipe");

    enum { MAX_PROBE = 4096 }; /* well above the internal PENDING_MAX */
    static int event_fds[MAX_PROBE];
    int filled = 0;

    for (int i = 0; i < MAX_PROBE; i++) {
        int efd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        ASSERT(efd >= 0, "open event fd");
        if (efd < 0)
            break;

        struct fanotify_event_metadata ev;
        memset(&ev, 0, sizeof(ev));
        ev.event_len = sizeof(ev);
        ev.vers = FANOTIFY_METADATA_VERSION;
        ev.mask = FAN_OPEN_PERM;
        ev.fd = efd;
        ev.pid = (int)getpid();

        if (fanotify_defer_event(&ev) == 0) {
            event_fds[filled++] = efd;
        } else {
            /* Queue full: caller contract is to fail closed. */
            close(efd);
            break;
        }
    }

    ASSERT(filled > 0, "deferred queue accepted events");
    ASSERT(fanotify_pending_count() == filled,
           "pending count matches deferred events");

    struct fanotify_event_metadata probe;
    memset(&probe, 0, sizeof(probe));
    probe.event_len = sizeof(probe);
    probe.vers = FANOTIFY_METADATA_VERSION;
    probe.mask = FAN_OPEN_PERM;
    probe.fd = -1; /* FAN_NOFD */
    probe.pid = (int)getpid();
    ASSERT(fanotify_defer_event(&probe) == -1,
           "defer into a full queue fails closed");

    /* Fail-closed flush: deny + close every deferred event. */
    fanotify_flush_pending(resp_pipe[1]);
    ASSERT(fanotify_pending_count() == 0, "queue empty after flush");

    /* Exactly one fanotify_response per deferred event must arrive. */
    size_t want = (size_t)filled * sizeof(struct fanotify_response);
    char *buf = malloc(want);
    ASSERT(buf != NULL, "alloc response buffer");
    size_t got = 0;
    while (got < want) {
        ssize_t n = read(resp_pipe[0], buf + got, want - got);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (n == 0)
            break;
        got += (size_t)n;
    }
    ASSERT(got == want, "one deny response per deferred event");

    for (int i = 0; i < filled; i++) {
        const struct fanotify_response *r =
            (const struct fanotify_response *)(buf +
                (size_t)i * sizeof(*r));
        ASSERT(r->response == FAN_DENY, "flush response is FAN_DENY");
        ASSERT(r->fd == event_fds[i],
               "flush response targets the deferred fd");
        ASSERT(r->response == FAN_DENY, "flush response is FAN_DENY");
        ASSERT(r->fd == event_fds[i],
               "flush response targets the deferred fd");
        ASSERT(fcntl(event_fds[i], F_GETFD) == -1 && errno == EBADF,
               "deferred fd was closed by flush");
    }

    free(buf);
    close(resp_pipe[0]);
    close(resp_pipe[1]);
}

/*
 * Part 2: real kernel fanotify group, no FAN_UNLIMITED_QUEUE.  Open 20000
 * distinct files under one marked directory without draining; the kernel
 * default queue holds 16384 events, so saturation is guaranteed and the
 * next read must report FAN_Q_OVERFLOW.
 */
static void test_kernel_bounded_queue_overflow(void) {
    int fd = fanotify_init(FAN_CLOEXEC | FAN_CLASS_NOTIF, O_RDONLY);
    if (fd < 0) {
        if (errno == EPERM || errno == ENOSYS || errno == EAGAIN) {
            printf("SKIP: fanotify group unavailable (%s); "
                   "run as root to exercise the kernel saturation test\n",
                   strerror(errno));
            return;
        }
        fprintf(stderr, "FAIL: fanotify_init: %s\n", strerror(errno));
        failures++;
        return;
    }

    char dir[] = "/tmp/fileshield_queue_sat_XXXXXX";
    if (!mkdtemp(dir)) {
        fprintf(stderr, "FAIL: mkdtemp: %s\n", strerror(errno));
        failures++;
        close(fd);
        return;
    }

    enum { SAT_FILES = 20000 }; /* > 16384 kernel default queue limit */

    /* Create files BEFORE marking so only the opens below queue events. */
    char path[PATH_MAX];
    for (int i = 0; i < SAT_FILES; i++) {
        snprintf(path, sizeof(path), "%s/f%05d", dir, i);
        int f = open(path, O_CREAT | O_WRONLY, 0600);
        if (f >= 0)
            close(f);
    }

    if (fanotify_mark(fd, FAN_MARK_ADD, FAN_OPEN | FAN_EVENT_ON_CHILD,
                      AT_FDCWD, dir) < 0) {
        fprintf(stderr, "FAIL: fanotify_mark: %s\n", strerror(errno));
        failures++;
        goto cleanup;
    }

    /* One open per distinct inode: 20000 unique events, no merging. */
    for (int i = 0; i < SAT_FILES; i++) {
        snprintf(path, sizeof(path), "%s/f%05d", dir, i);
        int o = open(path, O_RDONLY);
        if (o >= 0)
            close(o);
    }

    /* Drain everything and look for the overflow report. */
    int overflow_seen = 0;
    long events_drained = 0;
    char buf[65536]
        __attribute__((aligned(__alignof__(struct fanotify_event_metadata))));
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);

    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN)
                break;
            if (errno == EOVERFLOW) { /* overflow as a read error */
                overflow_seen = 1;
                break;
            }
            fprintf(stderr, "FAIL: fanotify read: %s\n", strerror(errno));
            failures++;
            break;
        }
        if (n == 0)
            break;

        const struct fanotify_event_metadata *ev =
            (const struct fanotify_event_metadata *)buf;
        ssize_t remaining = n;
        while (FAN_EVENT_OK(ev, (size_t)remaining)) {
            if (ev->mask & FAN_Q_OVERFLOW)
                overflow_seen = 1;
            if (ev->event_len == 0)
                break;
            remaining -= ev->event_len;
            ev = FAN_EVENT_NEXT(ev, remaining);
            events_drained++;
        }
    }

    ASSERT(overflow_seen, "FAN_Q_OVERFLOW reported after saturation");
    ASSERT(events_drained < SAT_FILES,
           "bounded queue dropped events instead of growing unbounded");

cleanup:
    for (int i = 0; i < SAT_FILES; i++) {
        snprintf(path, sizeof(path), "%s/f%05d", dir, i);
        unlink(path);
    }
    rmdir(dir);
    close(fd);
}

int main(void) {
    printf("=== test_fanotify ===\n");
    test_mark_mask_rejects_fid_events();
    test_missing_path_is_skipped();
    test_empty_target_entries_dropped();
    test_cmdline_scoping();
    test_defer_flush_contract();
    test_kernel_bounded_queue_overflow();
    if (failures) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("PASS\n");
    return 0;
}
