#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <limits.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>

#include "notify.h"
#include "fanotify.h"
#include "utils.h"

/* UID of the desktop user whose session was detected. 0 = not found. */
static uid_t g_session_uid = 0;

/*
 * Fanotify fd stored here so run_kdialog_3choice() can pump pending events
 * while waiting for the dialog child (prevents mount-mark deadlock).
 */
static int g_fan_fd = -1;

/* Total wall-clock budget for a dialog, slightly longer than the inner
 * "timeout 30" the child enforces. */
#define DIALOG_OUTER_TIMEOUT_S 40

void notify_set_fan_fd(int fd)
{
    g_fan_fd = fd;
}

/*
 * find_wayland_session: look for an active Wayland session owned by
 * uid_val under /run/user/<uid>.  On success exports WAYLAND_DISPLAY,
 * XDG_RUNTIME_DIR and DBUS_SESSION_BUS_ADDRESS, records g_session_uid,
 * and returns 1.
 */
static int find_wayland_session(unsigned long uid_val)
{
    char user_dir[PATH_MAX];
    DIR *d;
    struct dirent *ent;
    char wayland_sock[256] = "";

    snprintf(user_dir, sizeof(user_dir), "/run/user/%lu", uid_val);

    d = opendir(user_dir);
    if (!d)
        return 0;

    while ((ent = readdir(d)) != NULL)
    {
        if (strncmp(ent->d_name, "wayland-", 8) == 0 &&
            strstr(ent->d_name, ".lock") == NULL)
        {
            snprintf(wayland_sock, sizeof(wayland_sock), "%s", ent->d_name);
            break;
        }
    }
    closedir(d);

    if (wayland_sock[0] == '\0')
        return 0;

    setenv("WAYLAND_DISPLAY", wayland_sock, 1);
    setenv("XDG_RUNTIME_DIR", user_dir, 1);
    char dbus[PATH_MAX + 32];
    snprintf(dbus, sizeof(dbus), "unix:path=%s/bus", user_dir);
    setenv("DBUS_SESSION_BUS_ADDRESS", dbus, 1);
    g_session_uid = (uid_t)uid_val;
    return 1;
}

/*
 * setup_display_env: determine which desktop session should show the
 * prompt.  Preference order:
 *   1. Environment already provides WAYLAND_DISPLAY/DISPLAY (derive the
 *      session uid from XDG_RUNTIME_DIR ownership).
 *   2. The requesting process's own uid (preferred_uid): the prompt must
 *      be shown to the user whose process triggered it.
 *   3. As a last resort for unknown requesters, the first active non-root
 *      Wayland session found under /run/user.
 * The dialog child drops to g_session_uid; if no non-root session can be
 * determined, notify_ask() refuses to run a GUI as root.
 */
static void setup_display_env(uid_t preferred_uid)
{
    if (getenv("WAYLAND_DISPLAY") || getenv("DISPLAY"))
    {
        const char *xdg = getenv("XDG_RUNTIME_DIR");
        if (xdg)
        {
            struct stat st;
            if (stat(xdg, &st) == 0 && st.st_uid != 0)
                g_session_uid = st.st_uid;
        }
        return;
    }

    if (preferred_uid != (uid_t)-1 && preferred_uid != 0)
    {
        if (find_wayland_session((unsigned long)preferred_uid))
            return;
        log_msg(LOG_WARNING,
                "no active Wayland session for uid %d; not prompting another user",
                (int)preferred_uid);
        return;
    }

    DIR *top = opendir("/run/user");
    if (!top)
        return;

    struct dirent *uid_ent;
    while ((uid_ent = readdir(top)) != NULL)
    {
        if (uid_ent->d_name[0] == '.')
            continue;

        char *endptr;
        unsigned long uid_val = strtoul(uid_ent->d_name, &endptr, 10);
        if (*endptr != '\0' || uid_val == 0)
            continue;

        if (find_wayland_session(uid_val))
            break;
    }
    closedir(top);
}

/*
 * drop_to_session_user: called in the dialog child after fork().
 * Switches uid/gid to the desktop user (including supplementary groups)
 * so the dialog can connect to their compositor and D-Bus session.
 */
static void drop_to_session_user(void)
{
    if (g_session_uid == 0 || getuid() != 0)
        return;

    struct passwd *pw = getpwuid(g_session_uid);
    if (!pw)
        _exit(127);

    /* Drop supplementary groups first, then gid, then uid. */
    if (initgroups(pw->pw_name, pw->pw_gid) < 0)
        _exit(127);
    if (setgid(pw->pw_gid) < 0)
        _exit(127);
    if (setuid(g_session_uid) < 0)
        _exit(127);
    setenv("HOME", pw->pw_dir, 1);
}

/*
 * sanitize_text: replace control characters (including newlines) with
 * '?' and bound the length so attacker-controlled file names, comm names
 * and cmdlines cannot spoof extra dialog content.
 */
static void sanitize_text(const char *in, char *out, size_t outsz)
{
    size_t j = 0;

    if (outsz == 0)
        return;
    if (!in)
    {
        out[0] = '\0';
        return;
    }
    for (size_t i = 0; in[i] != '\0' && j + 1 < outsz; i++)
    {
        unsigned char c = (unsigned char)in[i];
        out[j++] = (c < 0x20 || c == 0x7f) ? '?' : (char)c;
    }
    out[j] = '\0';
}

/* Kill the dialog process group and reap with a bounded wait. */
static void kill_and_reap(pid_t pid, int *status, int *child_exited)
{
    kill(-pid, SIGKILL);
    for (int i = 0; i < 100 && !*child_exited; i++) /* up to ~10s */
    {
        pid_t wr = waitpid(pid, status, WNOHANG);
        if (wr == pid)
            *child_exited = 1;
        else if (wr < 0 && errno != EINTR)
            break;
        usleep(100000);
    }
    if (!*child_exited)
        log_msg(LOG_ERR,
                "[dialog] pid=%d did not exit after SIGKILL; abandoning it",
                (int)pid);
}

/*
 * run_kdialog_3choice: display a kdialog --yesnocancel prompt with custom
 * button labels and return the chosen button:
 *   0 = yes, 1 = no, 2 = cancel/window close, -1 = failure/timeout.
 *
 * kdialog is wrapped in timeout(1) so a hung compositor cannot block the
 * event loop forever.  While waiting, pending fanotify events are pumped:
 * kdialog opens its own config files, which can generate FAN_OPEN_PERM
 * events on mount-marked filesystems and would otherwise deadlock the
 * helper behind the daemon's blocked event.
 */
static int run_kdialog_3choice(const char *text, const char *yes_label,
                               const char *no_label, const char *cancel_label)
{
    pid_t pid = fork();
    if (pid < 0)
    {
        log_msg(LOG_ERR, "fork failed for kdialog: %m");
        return -1;
    }
    log_msg(LOG_DEBUG, "[dialog] forked kdialog child pid=%d", (int)pid);

    if (pid == 0)
    {
        /* Own process group so the timeout kill cannot touch the daemon
         * and so events from every dialog helper can be recognized. */
        setpgid(0, 0);
        drop_to_session_user();
        close_fds_from(3);

        execl("/usr/bin/timeout", "timeout", "30",
              "/usr/bin/kdialog", "kdialog",
              "--title", "FileShield",
              "--yesnocancel", text,
              "--yes-label", yes_label,
              "--no-label", no_label,
              "--cancel-label", cancel_label,
              (char *)NULL);
        _exit(127);
    }

    log_msg(LOG_DEBUG, "[dialog] parent waiting for kdialog (pid=%d)", (int)pid);
    int child_exited = 0;
    int status = 0;
    time_t deadline = time(NULL) + DIALOG_OUTER_TIMEOUT_S;

    while (!child_exited && time(NULL) < deadline)
    {
        struct pollfd pfd;
        int nfds = 0;

        if (g_fan_fd >= 0)
        {
            pfd.fd = g_fan_fd;
            pfd.events = POLLIN;
            pfd.revents = 0;
            nfds = 1;
        }

        int ret = poll(nfds ? &pfd : NULL, (nfds_t)nfds, 200); /* 200 ms tick */
        if (ret < 0)
        {
            if (errno == EINTR)
                continue;
            break;
        }

        /* Pump fanotify first so the dialog child is never stalled. */
        if (nfds && (pfd.revents & POLLIN))
            fanotify_pump(g_fan_fd, pid);

        /* Non-blocking child-exit check. */
        pid_t wr = waitpid(pid, &status, WNOHANG);
        if (wr == pid)
        {
            child_exited = 1;
        }
        else if (wr < 0 && errno != EINTR)
        {
            log_msg(LOG_ERR, "waitpid failed: %m");
            return -1;
        }
    }

    if (!child_exited)
    {
        log_msg(LOG_WARNING, "[dialog] kdialog outer timeout, killing pid=%d",
                (int)pid);
        kill_and_reap(pid, &status, &child_exited);
    }

    log_msg(LOG_DEBUG, "[dialog] kdialog exited status=0x%x ec=%d",
            status, WIFEXITED(status) ? WEXITSTATUS(status) : -1);

    /* A child killed by the outer timeout, an exec failure (127) or any
     * unexpected exit code is a failure: the caller fails closed. */
    if (!child_exited || !WIFEXITED(status))
        return -1;

    int ec = WEXITSTATUS(status);

    if (ec == 124) /* coreutils timeout(1) */
    {
        log_msg(LOG_WARNING, "[dialog] kdialog timed out (30s)");
        return -1;
    }
    if (ec == 0)
        return 0; /* Yes */
    if (ec == 1)
        return 1; /* No */
    if (ec == 2)
        return 2; /* Cancel / window close / Escape */
    return -1;
}

int notify_ask(const char *comm, pid_t pid, pid_t ppid,
               const char *comm_parent, const char *exe,
               const char *cmdline, const char *path, uid_t user_uid)
{
    /* Return values: NOTIFY_ALLOW_ONCE, NOTIFY_DENY,
     *                NOTIFY_ALLOW_SESSION, NOTIFY_DENY_SESSION,
     *                NOTIFY_ALLOW_ALWAYS, NOTIFY_DENY_ALWAYS. */
    char msg[2048];
    char msg2[1024];
    char comm_s[64];
    char pcomm_s[64];
    char cmd_s[256];
    char exe_s[512];
    char path_s[512];

    /* Attacker-controlled strings (file names, comm, cmdline) are
     * sanitized so control characters cannot forge dialog content. */
    sanitize_text(comm, comm_s, sizeof(comm_s));
    sanitize_text(comm_parent, pcomm_s, sizeof(pcomm_s));
    sanitize_text(exe ? exe : "(unknown)", exe_s, sizeof(exe_s));
    sanitize_text(path, path_s, sizeof(path_s));
    sanitize_text(cmdline && cmdline[0] != '\0' ? cmdline : "(unknown)",
                  cmd_s, sizeof(cmd_s));

    if (exe && strlen(exe) >= sizeof(exe_s) - 1)
        memcpy(exe_s + sizeof(exe_s) - 4, "...", 4);
    if (path && strlen(path) >= sizeof(path_s) - 1)
        memcpy(path_s + sizeof(path_s) - 4, "...", 4);
    if (cmdline && strlen(cmdline) >= sizeof(cmd_s) - 1)
        memcpy(cmd_s + sizeof(cmd_s) - 4, "...", 4);

    snprintf(msg, sizeof(msg),
             "Process %s (PID %d, parent: %s (PID %d)) wants to read:\n"
             "%s\n\n"
             "Binary:   %s\n"
             "Command:  %s\n\n"
             "\xe2\x80\xa2 Allow Once \xe2\x80\x94 this file, for the configured user_ttl\n"
             "\xe2\x80\xa2 Allow      \xe2\x80\x94 choose session or permanent access\n"
             "\xe2\x80\xa2 Deny       \xe2\x80\x94 choose a session or permanent block",
             comm_s, (int)pid, pcomm_s, (int)ppid,
             path_s, exe_s, cmd_s);

    /* Auto-detect the active graphical session if env vars are not set. */
    setup_display_env(user_uid);
    log_msg(LOG_DEBUG,
            "[notify_ask] display env: WAYLAND=%s DISPLAY=%s uid=%d",
            getenv("WAYLAND_DISPLAY") ? getenv("WAYLAND_DISPLAY") : "(none)",
            getenv("DISPLAY") ? getenv("DISPLAY") : "(none)",
            (int)g_session_uid);

    /* Never run a security prompt as a root GUI process. */
    if (getuid() == 0 && g_session_uid == 0)
    {
        log_msg(LOG_ERR,
                "no non-root desktop session found; denying access to %s",
                path_s);
        return NOTIFY_DENY;
    }

    /* First dialog: Allow Once / Allow / Deny. */
    int r = run_kdialog_3choice(msg, "Allow Once", "Allow", "Deny");

    if (r == 0)
        return NOTIFY_ALLOW_ONCE;

    if (r == 1)
    {
        /* Allow: choose how broad/long the grant should be.  Allow Always
         * is on the No button per the approved UX; a broken kdialog that
         * exits 1 without user interaction is a known accepted risk. */
        snprintf(msg2, sizeof(msg2),
                 "Allow access to:\n"
                 "%s\n\n"
                 "\xe2\x80\xa2 Allow Session \xe2\x80\x94 this file until this session closes\n"
                 "\xe2\x80\xa2 Allow Always  \xe2\x80\x94 this file permanently\n"
                 "                  (re-prompts if the binary changes)\n"
                 "\xe2\x80\xa2 Cancel        \xe2\x80\x94 deny this time",
                 path_s);

        int r2 = run_kdialog_3choice(msg2, "Allow Session", "Allow Always",
                                     "Cancel");
        if (r2 == 0)
            return NOTIFY_ALLOW_SESSION;
        if (r2 == 1)
            return NOTIFY_ALLOW_ALWAYS;
        return NOTIFY_DENY;
    }

    /* A failed first dialog (timeout, exec error) denies once without a
     * follow-up prompt; only an explicit Deny click opens the deny
     * dialog. */
    if (r != 2)
    {
        log_msg(LOG_WARNING, "[dialog] no valid kdialog choice; denying once");
        return NOTIFY_DENY;
    }

    snprintf(msg2, sizeof(msg2),
             "Deny access to:\n"
             "%s\n\n"
             "\xe2\x80\xa2 Deny Session \xe2\x80\x94 this file until this session closes\n"
             "\xe2\x80\xa2 Deny Always  \xe2\x80\x94 this file permanently\n"
             "                 (runtime-denylist.json)\n"
             "\xe2\x80\xa2 Deny         \xe2\x80\x94 this time only",
             path_s);

    int r3 = run_kdialog_3choice(msg2, "Deny Session", "Deny Always", "Deny");
    if (r3 == 0)
        return NOTIFY_DENY_SESSION;
    if (r3 == 1)
        return NOTIFY_DENY_ALWAYS;
    return NOTIFY_DENY;
}
