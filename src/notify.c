#include <errno.h>
#include <fcntl.h>
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
 * Fanotify fd stored here so run_dialog() can pump pending events while
 * waiting for the dialog child (prevents mount-mark deadlock).
 */
static int g_fan_fd = -1;

/* Total wall-clock budget for a dialog, slightly longer than the inner
 * "timeout 30" / zenity --timeout=30 the child enforces. */
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

/* Read whatever the pipe currently holds (non-blocking) into out. */
static void drain_pipe(int fd, char *out, size_t outsz, size_t *used)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    while (*used + 1 < outsz)
    {
        ssize_t n = read(fd, out + *used, outsz - 1 - *used);
        if (n > 0)
            *used += (size_t)n;
        else
            break;
    }
    out[*used] = '\0';
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

static int run_dialog(const char *bin, const char *text)
{
    /*
     * Three-choice dialog, one click per button:
     *   Allow Once    -> the configured TTL (user_ttl)
     *   Allow Session -> the caller's session subtree (session_ttl cap)
     *   Deny          -> deny this attempt
     * kdialog uses --yesnocancel with explicit labels; zenity uses
     * --question --extra-button (the extra button prints its label to
     * stdout).  Any timeout, close or runtime error returns -1 and the
     * caller denies without a grant.
     */
    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) < 0)
    {
        log_msg(LOG_ERR, "pipe failed for dialog: %m");
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0)
    {
        close(pipefd[0]);
        close(pipefd[1]);
        log_msg(LOG_ERR, "fork failed for %s: %m", bin);
        return -1;
    }
    log_msg(LOG_DEBUG, "[dialog] forked %s child pid=%d", bin, (int)pid);

    if (pid == 0)
    {
        setpgid(0, 0);
        drop_to_session_user();
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0)
            _exit(127);
        if (pipefd[1] != STDOUT_FILENO)
            close(pipefd[1]);
        close_fds_from(3);

        if (strcmp(bin, "zenity") == 0)
        {
            /*
             * Three buttons:
             *   Allow Once    → OK button     → exit 0
             *   Allow Session → extra-button  → exit 1 + stdout="Allow Session"
             *   Deny          → Cancel button → exit 1 + stdout=""
             * Timeout (30 s) → exit 5
             */
            execl("/usr/bin/zenity", "zenity",
                  "--question", "--title=FileShield", "--no-markup",
                  "--timeout=30",
                  "--text", text,
                  "--width=600",
                  "--ok-label=Allow Once",
                  "--cancel-label=Deny",
                  "--extra-button=Allow Session",
                  (char *)NULL);
        }
        else
        {
            /*
             * kdialog --yesnocancel with explicit labels:
             *   Allow Once    → Yes    → exit 0
             *   Allow Session → No     → exit 1
             *   Deny          → Cancel → exit 2
             * Window close / Escape → Cancel.
             * Timeout via coreutils timeout(1) → exit 124.
             */
            execl("/usr/bin/timeout", "timeout", "30",
                  "/usr/bin/kdialog", "kdialog",
                  "--title", "FileShield",
                  "--yesnocancel", text,
                  "--yes-label", "Allow Once",
                  "--no-label", "Allow Session",
                  "--cancel-label", "Deny",
                  (char *)NULL);
        }
        _exit(127);
    }

    /* Parent: close write end, then wait for child using a poll loop.
     *
     * Rationale: when FAN_MARK_MOUNT is active kdialog opens config files
     * on the same filesystem (e.g. ~/.config/kdeglobals) which generates
     * FAN_OPEN_PERM events.  A blocking waitpid() would deadlock because
     * the daemon can't respond to those events.  We pump the fanotify fd
     * on every iteration to keep the kernel queue drained. */
    close(pipefd[1]);
    log_msg(LOG_DEBUG, "[dialog] parent waiting for %s (pid=%d)", bin, (int)pid);
    char out[64] = "";
    size_t out_len = 0;
    int child_exited = 0;
    int status = 0;

    time_t deadline = time(NULL) + DIALOG_OUTER_TIMEOUT_S;

    while (!child_exited && time(NULL) < deadline)
    {
        struct pollfd pfds[2];
        int nfds = 0;

        pfds[nfds].fd = pipefd[0];
        pfds[nfds].events = POLLIN;
        nfds++;

        if (g_fan_fd >= 0)
        {
            pfds[nfds].fd = g_fan_fd;
            pfds[nfds].events = POLLIN;
            nfds++;
        }

        int ret = poll(pfds, (nfds_t)nfds, 200); /* 200 ms tick */
        if (ret < 0)
        {
            if (errno == EINTR)
                continue;
            break;
        }

        /* Pump fanotify first so the dialog child is never stalled. */
        for (int i = 0; i < nfds; i++)
        {
            if (pfds[i].fd == g_fan_fd && (pfds[i].revents & POLLIN))
                fanotify_pump(g_fan_fd, pid);
        }

        /* Collect dialog output if readable. */
        for (int i = 0; i < nfds; i++)
        {
            if (pfds[i].fd == pipefd[0] &&
                (pfds[i].revents & (POLLIN | POLLHUP)) &&
                out_len + 1 < sizeof(out))
            {
                drain_pipe(pipefd[0], out, sizeof(out), &out_len);
                break;
            }
        }

        /* Non-blocking child-exit check. */
        pid_t wr = waitpid(pid, &status, WNOHANG);
        if (wr == pid)
        {
            child_exited = 1;
        }
        else if (wr < 0 && errno != EINTR)
        {
            log_msg(LOG_ERR, "waitpid failed: %m");
            close(pipefd[0]);
            return -1;
        }
    }

    if (!child_exited)
    {
        log_msg(LOG_WARNING, "[dialog] %s outer timeout, killing pid=%d",
                bin, (int)pid);
        kill_and_reap(pid, &status, &child_exited);
    }

    /* Drain any final output before interpreting the exit code. */
    drain_pipe(pipefd[0], out, sizeof(out), &out_len);
    close(pipefd[0]);
    log_msg(LOG_DEBUG, "[dialog] %s exited status=0x%x ec=%d",
            bin, status, WIFEXITED(status) ? WEXITSTATUS(status) : -1);

    if (!child_exited || !WIFEXITED(status))
        return -1;

    int ec = WEXITSTATUS(status);

    if (strcmp(bin, "zenity") == 0)
    {
        if (ec == 5) /* timeout */
            return -1;
        if (ec == 0)
            return NOTIFY_ALLOW_ONCE; /* OK */
        /* ec == 1: extra-button OR Cancel — distinguish by stdout */
        if (strncmp(out, "Allow Session", 13) == 0)
            return NOTIFY_ALLOW_SESSION;
        return NOTIFY_DENY; /* Cancel / Deny */
    }

    /*
     * kdialog --yesnocancel:
     *   Yes=0 Allow Once, No=1 Allow Session, Cancel=2 Deny;
     *   window close/Escape map to Cancel.
     */
    if (ec == 124) /* timeout */
        return -1;
    if (ec == 0)
        return NOTIFY_ALLOW_ONCE;
    if (ec == 1)
        return NOTIFY_ALLOW_SESSION;
    if (ec == 2)
        return NOTIFY_DENY;
    return -1; /* error → deny once */
}

int notify_ask(const char *comm, pid_t pid, pid_t ppid,
               const char *comm_parent, const char *exe,
               const char *cmdline, const char *path, uid_t user_uid)
{
    /* Return values: NOTIFY_ALLOW_ONCE, NOTIFY_ALLOW_SESSION, NOTIFY_DENY. */
    char msg[2048];
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
             "\xe2\x80\xa2 Allow Once    \xe2\x80\x94 grant access this time only\n"
             "\xe2\x80\xa2 Allow Session \xe2\x80\x94 allow this binary while this\n"
             "                terminal session lasts\n"
             "\xe2\x80\xa2 Deny          \xe2\x80\x94 block this attempt",
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

    if (getenv("WAYLAND_DISPLAY"))
    {
        int r = run_dialog("kdialog", msg);
        if (r == NOTIFY_ALLOW_ONCE || r == NOTIFY_ALLOW_SESSION ||
            r == NOTIFY_DENY)
            return r;
        log_msg(LOG_WARNING, "kdialog failed, falling back to zenity");
    }

    if (getenv("DISPLAY"))
    {
        int r = run_dialog("zenity", msg);
        if (r == NOTIFY_ALLOW_ONCE || r == NOTIFY_ALLOW_SESSION ||
            r == NOTIFY_DENY)
            return r;
        log_msg(LOG_WARNING, "zenity failed");
    }

    log_msg(LOG_ERR, "no graphical dialog available; denying access to %s", path_s);
    return NOTIFY_DENY;
}
