/*
 * phase0_mark_scope.c — Phase 0 experiments for MARK-SCOPE-REDESIGN.md
 *
 * These experiments answer the questions the mark-scope redesign depends
 * on.  Each run mounts its own private tmpfs at /tmp/fileshield-phase0-<pid>
 * and only ever marks that mount or its superblock.  Nothing else on the
 * system is intercepted, so the runs are safe on a daily-driver machine —
 * still, run them on a disposable VM first per the redesign document.
 *
 *   exp1  FAN_MARK_MOUNT placed inside a private mount namespace: does an
 *         open made through the init-namespace mount fire an event?
 *         Expected: NO.  A mark lives on one mount instance, and namespace
 *         copies do not inherit marks (this is the coverage bug).
 *
 *   exp2  Option B proof: mark the init-namespace mount from inside the
 *         private namespace via /proc/<init-ns-child>/root/<path>.
 *         If events fire, the systemd sandbox can be preserved.
 *
 *   exp3  FAN_MARK_FILESYSTEM on the scratch tmpfs superblock: does an open
 *         through the init namespace fire?
 *         Expected: YES (superblock scope is shared across namespaces).
 *
 *   exp2p Sandbox probe: run under the real unit sandbox options and check
 *         that /proc/1/root is visible and a mount mark can be placed
 *         through it.  Delivery mechanics are already proven by exp2.
 *         PrivateTmp=yes gives the unit a private /tmp, so the binary must
 *         live outside /tmp; install it first.  Run with:
 *           cd /home/micah/Projects/FileShield
 *           gcc -std=c99 -Wall -Wextra -Wpedantic -Werror -O2 \
 *               -o /tmp/phase0 experiments/phase0_mark_scope.c
 *           sudo install -m 0755 /tmp/phase0 /usr/local/bin/phase0
 *           sudo systemd-run --wait --collect -p ProtectSystem=strict \
 *             -p ProtectProc=invisible -p PrivateDevices=yes \
 *             -p PrivateTmp=yes -p RuntimeDirectory=fileshield-phase0 \
 *             /usr/local/bin/phase0 exp2p
 *
 * Build:
 *   gcc -std=c99 -Wall -Wextra -Wpedantic -Werror -O2 \
 *       -o /tmp/phase0 experiments/phase0_mark_scope.c
 *
 * Run (as root):
 *   sudo /tmp/phase0 exp1
 *   sudo /tmp/phase0 exp2
 *   sudo /tmp/phase0 exp3
 *   (exp2p: see the systemd-run command above)
 *
 * Exit status: 0 = a verdict was printed, 1 = setup/permission failure.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fanotify.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define SCRATCH_BASE "/tmp/fileshield-phase0"
#define CHILD_TIMEOUT_MS 30000
#define EVENT_TIMEOUT_MS 2000

static char g_dir[128];
static char g_file[192];
static int g_mounted;

/* ------------------------------------------------------------------ */
/*  scratch tmpfs                                                      */
/* ------------------------------------------------------------------ */

static int setup_scratch(void)
{
    snprintf(g_dir, sizeof(g_dir), SCRATCH_BASE "-%d", (int)getpid());
    snprintf(g_file, sizeof(g_file), "%s/secret", g_dir);

    if (mkdir(g_dir, 0700) < 0)
    {
        fprintf(stderr, "mkdir %s: %s\n", g_dir, strerror(errno));
        return -1;
    }
    if (mount("tmpfs", g_dir, "tmpfs", 0, "mode=0700") < 0)
    {
        fprintf(stderr, "mount tmpfs on %s: %s\n", g_dir, strerror(errno));
        return -1;
    }
    g_mounted = 1;

    int fd = open(g_file, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0 || write(fd, "phase0", 6) != 6)
    {
        fprintf(stderr, "create %s: %s\n", g_file, strerror(errno));
        if (fd >= 0)
            close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static void teardown(void)
{
    if (g_mounted)
    {
        umount(g_dir);
        rmdir(g_dir);
        g_mounted = 0;
    }
}

/* ------------------------------------------------------------------ */
/*  children                                                           */
/* ------------------------------------------------------------------ */

struct child
{
    pid_t pid;
    int cmd_fd;  /* parent writes a byte to let the child open the file */
    int ack_fd;  /* child writes '1' (open ok) or '0'                  */
    int unmount; /* unmount the init-namespace scratch mount at the end */
};

static void child_main(int cmd_fd, int ack_fd, int unmount)
{
    struct pollfd p = { .fd = cmd_fd, .events = POLLIN };
    char b;

    if (poll(&p, 1, CHILD_TIMEOUT_MS) <= 0)
        _exit(21);
    if (read(cmd_fd, &b, 1) != 1)
        _exit(22);

    int fd = open(g_file, O_RDONLY);
    int ok = (fd >= 0);
    if (ok)
        close(fd);
    if (write(ack_fd, ok ? "1" : "0", 1) != 1)
        _exit(23);

    p.revents = 0;
    if (poll(&p, 1, CHILD_TIMEOUT_MS) <= 0)
        _exit(24);
    if (read(cmd_fd, &b, 1) != 1)
        _exit(25);
    if (unmount)
        umount(g_dir);
    _exit(0);
}

static struct child spawn_child(int unmount)
{
    struct child c = { .pid = -1, .cmd_fd = -1, .ack_fd = -1, .unmount = unmount };
    int cmd[2];
    int ack[2];

    if (pipe(cmd) < 0 || pipe(ack) < 0)
    {
        perror("pipe");
        return c;
    }
    c.pid = fork();
    if (c.pid < 0)
    {
        perror("fork");
        return c;
    }
    if (c.pid == 0)
    {
        close(cmd[1]);
        close(ack[0]);
        child_main(cmd[0], ack[1], unmount);
        _exit(20);
    }
    close(cmd[0]);
    close(ack[1]);
    c.cmd_fd = cmd[1];
    c.ack_fd = ack[0];
    return c;
}

/* Let a child exit gracefully (it unmounts the init-ns scratch first).
 * The ack pipe is closed only after the wait: a child may still write its
 * open() result, and closing early delivers SIGPIPE. */
static void finish_child(struct child *c)
{
    int status = 0;
    int exited = 0;

    if (c->cmd_fd >= 0)
        (void)write(c->cmd_fd, "x", 1);

    if (c->pid > 0)
    {
        for (int i = 0; i < 300; i++) /* up to 3 s */
        {
            pid_t w = waitpid(c->pid, &status, WNOHANG);
            if (w == c->pid)
            {
                exited = 1;
                break;
            }
            if (w < 0 && errno != EINTR)
                break;
            usleep(10000);
        }
        if (!exited)
        {
            fprintf(stderr, "  warning: child %d did not exit; killing\n",
                    (int)c->pid);
            kill(c->pid, SIGKILL);
            waitpid(c->pid, NULL, 0);
            if (c->unmount)
                fprintf(stderr,
                        "  warning: %s may still be mounted in the init "
                        "namespace\n",
                        g_dir);
        }
        else if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        {
            fprintf(stderr, "  warning: child %d exit status 0x%x\n",
                    (int)c->pid, status);
        }
        c->pid = -1;
    }

    if (c->cmd_fd >= 0)
    {
        close(c->cmd_fd);
        c->cmd_fd = -1;
    }
    if (c->ack_fd >= 0)
    {
        close(c->ack_fd);
        c->ack_fd = -1;
    }
}

/* ------------------------------------------------------------------ */
/*  fanotify                                                           */
/* ------------------------------------------------------------------ */

/* Returns 1 when an event was read and allowed, 0 on timeout, -1 on error. */
static int wait_allow_event(int fan_fd, int timeout_ms)
{
    struct pollfd p = { .fd = fan_fd, .events = POLLIN };

    if (poll(&p, 1, timeout_ms) <= 0)
        return 0;

    char buf[4096]
        __attribute__((aligned(__alignof__(struct fanotify_event_metadata))));
    ssize_t n = read(fan_fd, buf, sizeof(buf));
    if (n < (ssize_t)FAN_EVENT_METADATA_LEN)
        return -1;

    const struct fanotify_event_metadata *ev =
        (const struct fanotify_event_metadata *)buf;
    if (ev->fd >= 0)
    {
        struct fanotify_response resp;
        resp.fd = ev->fd;
        resp.response = FAN_ALLOW;
        if (write(fan_fd, &resp, sizeof(resp)) < 0)
            perror("fanotify response");
        close((int)ev->fd);
    }
    return 1;
}

static int read_byte(int fd, int timeout_ms)
{
    if (fd < 0)
        return -1;
    struct pollfd p = { .fd = fd, .events = POLLIN };
    if (poll(&p, 1, timeout_ms) <= 0)
        return -1;
    char b;
    return read(fd, &b, 1) == 1 ? (unsigned char)b : -1;
}

/* Raw fdinfo is the only way to see what the kernel actually recorded. */
static void dump_fdinfo(int fan_fd)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fan_fd);

    FILE *fp = fopen(path, "r");
    if (!fp)
        return;
    printf("  fdinfo:\n");
    char line[256];
    while (fgets(line, sizeof(line), fp))
        printf("    %s", line);
    fclose(fp);
}

/* ------------------------------------------------------------------ */
/*  verdicts                                                           */
/* ------------------------------------------------------------------ */

static void verdict(const char *mode, int ev_a, int ev_b)
{
    if (strcmp(mode, "exp1") == 0)
    {
        if (ev_b != 1)
            printf("  VERDICT: INCONCLUSIVE — the private-ns control did not "
                   "fire; fix the harness before trusting this result\n");
        else if (ev_a == 1)
            printf("  VERDICT: mount marks DO cross mount namespaces on this "
                   "kernel; the redesign premise is wrong — stop and "
                   "re-evaluate\n");
        else
            printf("  VERDICT: CONFIRMED — mount marks do not cross mount "
                   "namespaces; the unit must not run in a private mount "
                   "namespace (Option A), or Option B must be proven\n");
    }
    else if (strcmp(mode, "exp2") == 0)
    {
        if (ev_a == 1)
            printf("  VERDICT: Option B WORKS — mount marks can be placed on "
                   "init-namespace mounts via /proc/<pid>/root; the systemd "
                   "sandbox can be preserved (with the D2 scope guard)\n");
        else
            printf("  VERDICT: Option B UNSUPPORTED — no event via "
                   "/proc/<pid>/root marking; fall back to Option A (drop "
                   "namespace-creating sandboxing)\n");
    }
    else
    {
        if (ev_a == 1)
            printf("  VERDICT: CONFIRMED — FAN_MARK_FILESYSTEM delivers across "
                   "namespaces (superblock scope); only safe on a dedicated "
                   "filesystem, never / or /home\n");
        else
            printf("  VERDICT: INCONCLUSIVE — no cross-namespace event from a "
                   "filesystem mark; recheck the harness\n");
    }
}

/* ------------------------------------------------------------------ */
/*  exp2p — sandbox visibility probe                                   */
/* ------------------------------------------------------------------ */
/*
 * Run under the unit's actual sandbox options (see the file header).
 * Verifies that /proc/1/root is reachable and that a mount mark can be
 * placed through it.  Delivery mechanics are already proven by exp2.
 */
static int probe_sandbox(void)
{
    const char *probe = "/proc/1/root/run/fileshield-phase0";
    struct stat st;
    int rc = 0;

    printf("=== exp2p (sandbox visibility probe) ===\n");

    if (stat("/proc/1/root", &st) == 0)
        printf("  /proc/1/root     : stat ok (mode %o, uid %d)\n",
               (unsigned)(st.st_mode & 07777), (int)st.st_uid);
    else
    {
        printf("  /proc/1/root     : stat FAILED: %s\n", strerror(errno));
        rc = 1;
    }

    int dirfd = open("/proc/1/root", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd >= 0)
    {
        printf("  /proc/1/root     : open ok\n");
        close(dirfd);
    }
    else
    {
        printf("  /proc/1/root     : open FAILED: %s\n", strerror(errno));
        rc = 1;
    }

    if (stat(probe, &st) != 0)
    {
        printf("  %s: stat: %s\n", probe, strerror(errno));
        printf("  (start via systemd-run with "
               "RuntimeDirectory=fileshield-phase0)\n");
        rc = 1;
    }

    int fan_fd = fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK,
                               O_RDONLY);
    if (fan_fd < 0)
    {
        printf("  fanotify_init    : FAILED: %s\n", strerror(errno));
        rc = 1;
    }
    else
    {
        if (fanotify_mark(fan_fd, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_OPEN_PERM,
                          AT_FDCWD, probe) == 0)
        {
            printf("  mark via proc root: ok\n");
            dump_fdinfo(fan_fd);
            (void)fanotify_mark(fan_fd, FAN_MARK_REMOVE | FAN_MARK_MOUNT,
                                FAN_OPEN_PERM, AT_FDCWD, probe);
        }
        else
        {
            printf("  mark via proc root: FAILED: %s\n", strerror(errno));
            rc = 1;
        }
        close(fan_fd);
    }

    printf(rc == 0
               ? "  VERDICT: Option B viable under the sandbox\n"
               : "  VERDICT: sandbox blocks /proc/1/root access or marking; "
                 "Option B is not viable as-is\n");
    return rc;
}

/* ------------------------------------------------------------------ */
/*  experiment driver                                                  */
/* ------------------------------------------------------------------ */

static int run(const char *mode)
{
    struct child a = { .pid = -1, .cmd_fd = -1, .ack_fd = -1 };
    struct child b = { .pid = -1, .cmd_fd = -1, .ack_fd = -1 };
    int fan_fd = -1;
    int mark_added = 0;
    unsigned int mark_flag = FAN_MARK_MOUNT;
    char mark_path[512] = "";
    int have_control = (strcmp(mode, "exp2") != 0);
    int ev_a = 0;
    int ev_b = 0;
    int ok_a = 0;
    int rc = 1;

    if (setup_scratch() < 0)
        return 1;

    printf("=== %s ===\n", mode);
    printf("  scratch : %s (private tmpfs)\n", g_dir);

    /* Child A stays in the init mount namespace. */
    a = spawn_child(1);
    if (a.pid < 0)
        goto out;

    if (unshare(CLONE_NEWNS) < 0)
    {
        fprintf(stderr, "unshare(CLONE_NEWNS): %s\n", strerror(errno));
        goto out;
    }
    /* No propagation: teardown must not unmount the init-ns mount. */
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0)
        fprintf(stderr, "  note: could not make mounts private: %s\n",
                strerror(errno));

    if (strcmp(mode, "exp2") == 0)
        snprintf(mark_path, sizeof(mark_path), "/proc/%d/root%s", (int)a.pid,
                 g_dir);
    else
        snprintf(mark_path, sizeof(mark_path), "%s", g_dir);

    if (strcmp(mode, "exp3") == 0)
        mark_flag = FAN_MARK_FILESYSTEM;

    fan_fd = fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK,
                           O_RDONLY);
    if (fan_fd < 0)
    {
        fprintf(stderr, "fanotify_init: %s\n", strerror(errno));
        goto out;
    }

    printf("  mark    : %s [%s]\n", mark_path,
           mark_flag == FAN_MARK_FILESYSTEM ? "filesystem" : "mount");
    if (fanotify_mark(fan_fd, FAN_MARK_ADD | mark_flag, FAN_OPEN_PERM,
                      AT_FDCWD, mark_path) < 0)
    {
        fprintf(stderr, "fanotify_mark ADD: %s\n", strerror(errno));
        goto out;
    }
    mark_added = 1;
    dump_fdinfo(fan_fd);

    /* Positive control: a child in the private namespace shares the mount
     * instance the mark was placed on (not meaningful for exp2). */
    if (have_control)
    {
        int ok_b;
        b = spawn_child(0); /* inherits the private namespace */
        if (b.pid < 0)
            goto out;
        if (write(b.cmd_fd, "b", 1) != 1)
            goto out;
        ev_b = wait_allow_event(fan_fd, EVENT_TIMEOUT_MS);
        ok_b = read_byte(b.ack_fd, CHILD_TIMEOUT_MS) == '1';
        printf("  control (private-ns child %d): event=%s open=%s\n",
               (int)b.pid, ev_b == 1 ? "YES" : ev_b == 0 ? "no" : "error",
               ok_b ? "ok" : "blocked");
    }

    /* The question under test: a child in the init namespace. */
    if (write(a.cmd_fd, "a", 1) != 1)
        goto out;
    ev_a = wait_allow_event(fan_fd, EVENT_TIMEOUT_MS);
    ok_a = read_byte(a.ack_fd, CHILD_TIMEOUT_MS) == '1';
    printf("  init-ns child %d: event=%s open=%s\n", (int)a.pid,
           ev_a == 1 ? "YES" : ev_a == 0 ? "no" : "error",
           ok_a ? "ok" : "blocked");

    verdict(mode, ev_a, ev_b);
    rc = 0;

out:
    if (fan_fd >= 0 && mark_added)
        (void)fanotify_mark(fan_fd, FAN_MARK_REMOVE | mark_flag,
                            FAN_OPEN_PERM, AT_FDCWD, mark_path);
    finish_child(&a);
    finish_child(&b);
    if (fan_fd >= 0)
        close(fan_fd);
    teardown();
    return rc;
}

int main(int argc, char **argv)
{
    if (argc != 2 ||
        (strcmp(argv[1], "exp1") != 0 && strcmp(argv[1], "exp2") != 0 &&
         strcmp(argv[1], "exp3") != 0 && strcmp(argv[1], "exp2p") != 0))
    {
        fprintf(stderr,
                "usage: %s exp1|exp2|exp3|exp2p\n"
                "  see experiments/phase0_mark_scope.c and "
                "MARK-SCOPE-REDESIGN.md (Phase 0)\n",
                argv[0]);
        return 2;
    }
    if (geteuid() != 0)
    {
        fprintf(stderr, "%s: must run as root (CAP_SYS_ADMIN)\n", argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "exp2p") == 0)
        return probe_sandbox();
    return run(argv[1]);
}
